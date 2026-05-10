from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from api import router
from database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Voidwatch Backend", version="0.1.0", lifespan=lifespan)
app.include_router(router)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
