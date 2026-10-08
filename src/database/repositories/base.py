from typing import TypeVar, Generic, Type, Optional, List, Any
from sqlalchemy.orm import Session
from src.database.models.base import Base

ModelType = TypeVar("ModelType", bound=Base)


class BaseRepository(Generic[ModelType]):
    """
    Generic base repository providing CRUD and transactional helpers.
    """
    def __init__(self, model: Type[ModelType], db: Session):
        self.model = model
        self.db = db

    def get_by_id(self, id_val: Any) -> Optional[ModelType]:
        return self.db.query(self.model).filter(self.model.id == id_val).first()

    def get_all(self, skip: int = 0, limit: int = 100) -> List[ModelType]:
        query = self.db.query(self.model)
        if hasattr(self.model, "is_deleted"):
            query = query.filter(self.model.is_deleted == False)
        return query.offset(skip).limit(limit).all()

    def create(self, obj_in: ModelType) -> ModelType:
        self.db.add(obj_in)
        self.db.commit()
        self.db.refresh(obj_in)
        return obj_in

    def update(self, obj: ModelType) -> ModelType:
        self.db.commit()
        self.db.refresh(obj)
        return obj

    def soft_delete(self, obj: ModelType) -> None:
        if hasattr(obj, "is_deleted"):
            from datetime import datetime, timezone
            obj.is_deleted = True
            obj.deleted_at = datetime.now(timezone.utc)
            self.db.commit()
        else:
            self.db.delete(obj)
            self.db.commit()
