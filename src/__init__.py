from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from src.db.main import init_db
from src.auth.routes import auth_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("server is starting")
    
    await init_db()
    yield

    print("server has been stopped")


app = FastAPI(
    title="auth",
    description="simple auth setup",
    lifespan=lifespan
)

@app.get("/", tags=["Health"])
def health_check():
    return "server working"


@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc:HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content = {
            "success": False,
            "message": exc.detail,
            "data": None
        }
    )

app.include_router(auth_router, prefix="/api/auth", tags=["Authentication"])