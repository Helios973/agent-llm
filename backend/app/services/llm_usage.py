from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.models import LLMUsage, User


def _month_start() -> datetime:
    now = datetime.now(timezone.utc)
    return datetime(now.year, now.month, 1, tzinfo=timezone.utc)


def usage_summary(db: Session, user_id: str) -> dict[str, int]:
    row = db.execute(
        select(
            func.coalesce(func.sum(LLMUsage.input_tokens), 0),
            func.coalesce(func.sum(LLMUsage.output_tokens), 0),
            func.coalesce(func.sum(LLMUsage.total_tokens), 0),
            func.count(LLMUsage.id),
        ).where(LLMUsage.user_id == user_id, LLMUsage.created_at >= _month_start())
    ).one()
    user = db.get(User, user_id)
    limit = user.monthly_token_limit if user else settings.llm_default_monthly_token_limit
    return {
        "monthly_token_limit": int(limit),
        "input_tokens": int(row[0]),
        "output_tokens": int(row[1]),
        "total_tokens": int(row[2]),
        "request_count": int(row[3]),
    }


def ensure_quota(db: Session, user_id: str, projected_tokens: int) -> None:
    summary = usage_summary(db, user_id)
    limit = summary["monthly_token_limit"]
    if limit > 0 and summary["total_tokens"] + projected_tokens > limit:
        raise HTTPException(status_code=429, detail="Monthly LLM token quota exceeded")


def record_usage(
    db: Session,
    *,
    user_id: str,
    task_id: str,
    provider: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
) -> None:
    db.add(
        LLMUsage(
            id=str(uuid4()),
            user_id=user_id,
            task_id=task_id,
            provider=provider,
            model=model,
            input_tokens=max(input_tokens, 0),
            output_tokens=max(output_tokens, 0),
            total_tokens=max(input_tokens, 0) + max(output_tokens, 0),
        )
    )
    db.commit()


def usage_analytics(db: Session, user_id: str, period: str = "all") -> dict[str, object]:
    today = datetime.now(timezone.utc).date()
    period_days = {"7d": 7, "30d": 30}.get(period)
    statement = select(LLMUsage).where(LLMUsage.user_id == user_id)
    if period_days:
        start_at = datetime.combine(today - timedelta(days=period_days - 1), datetime.min.time(), tzinfo=timezone.utc)
        statement = statement.where(LLMUsage.created_at >= start_at)
    rows = db.execute(statement.order_by(LLMUsage.created_at.asc())).scalars().all()

    def as_utc(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    active_dates = {as_utc(row.created_at).date() for row in rows}
    day_tokens: dict[date, int] = defaultdict(int)
    day_requests: dict[date, int] = defaultdict(int)
    hour_requests: Counter[int] = Counter()
    model_requests: Counter[tuple[str, str]] = Counter()
    model_values: dict[tuple[str, str], dict[str, int]] = defaultdict(
        lambda: {"request_count": 0, "input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
    )
    session_keys: set[str] = set()
    for row in rows:
        created_at = as_utc(row.created_at)
        current_date = created_at.date()
        day_tokens[current_date] += row.total_tokens
        day_requests[current_date] += 1
        hour_requests[created_at.hour] += 1
        key = (row.provider, row.model)
        model_requests[key] += 1
        values = model_values[key]
        values["request_count"] += 1
        values["input_tokens"] += row.input_tokens
        values["output_tokens"] += row.output_tokens
        values["total_tokens"] += row.total_tokens
        session_keys.add(row.task_id or row.id)

    longest_streak = 0
    running_streak = 0
    previous: date | None = None
    for active_date in sorted(active_dates):
        running_streak = running_streak + 1 if previous and active_date == previous + timedelta(days=1) else 1
        longest_streak = max(longest_streak, running_streak)
        previous = active_date

    current_streak = 0
    cursor = today if today in active_dates else today - timedelta(days=1)
    while cursor in active_dates:
        current_streak += 1
        cursor -= timedelta(days=1)

    heatmap_days = period_days or 182
    heatmap_start = today - timedelta(days=heatmap_days - 1)
    maximum = max((day_tokens[heatmap_start + timedelta(days=index)] for index in range(heatmap_days)), default=0)
    heatmap: list[dict[str, object]] = []
    for index in range(heatmap_days):
        current_date = heatmap_start + timedelta(days=index)
        tokens = day_tokens[current_date]
        level = 0 if tokens == 0 or maximum == 0 else min(4, max(1, (tokens * 4 + maximum - 1) // maximum))
        heatmap.append(
            {
                "date": current_date.isoformat(),
                "total_tokens": tokens,
                "request_count": day_requests[current_date],
                "level": level,
            }
        )

    total_tokens = sum(row.total_tokens for row in rows)
    models = []
    for (provider, model), values in sorted(
        model_values.items(), key=lambda item: (-item[1]["total_tokens"], item[0][1].casefold())
    ):
        models.append(
            {
                "provider": provider,
                "model": model,
                **values,
                "percentage": round(values["total_tokens"] * 100 / total_tokens, 2) if total_tokens else 0.0,
            }
        )

    favorite = model_requests.most_common(1)[0][0][1] if model_requests else None
    peak_hour = hour_requests.most_common(1)[0][0] if hour_requests else None
    return {
        "period": period,
        "sessions": len(session_keys),
        "messages": len(rows) * 2,
        "total_tokens": total_tokens,
        "active_days": len(active_dates),
        "current_streak": current_streak,
        "longest_streak": longest_streak,
        "peak_hour": peak_hour,
        "favorite_model": favorite,
        "heatmap": heatmap,
        "models": models,
    }
