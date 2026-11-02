from dataclasses import dataclass

from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from raven.extensions import db


@dataclass
class VideoStreamGroup(db.Model):
    """Which groups may see a video stream (see raven/group_isolation.py).

    A stream with no rows here is visible to everyone, which is what every
    stream added before group isolation existed looks like.
    """

    __tablename__ = "video_streams_groups"

    # video_streams.path is the primary key and does get rewritten, hence onupdate
    video_stream_path: Mapped[str] = mapped_column(
        String(255),
        ForeignKey("video_streams.path", ondelete="CASCADE", onupdate="CASCADE"),
        primary_key=True,
    )
    group_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True
    )
