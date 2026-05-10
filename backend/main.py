from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from api import router
from classifier import classifier
from database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    classifier.load_or_train()
    yield


app = FastAPI(title="Voidwatch Backend", version="0.2.0", lifespan=lifespan)
app.include_router(router)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False, log_level="critical")
