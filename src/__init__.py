from fastapi import FastAPI, Request, HTTPException, status
from fastapi.exceptions import RequestValidationError
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

def format_validation_errors(errors):
    formatted = []
    for err in errors:
        # Skip the first element if it's "body", "query", etc.
        loc = err["loc"]
        field = ".".join(str(l) for l in loc[1:]) if len(loc) > 1 else str(loc[0])
        formatted.append({
            "field": field,
            "message": err["msg"]
        })
    return formatted

@app.exception_handler(RequestValidationError)
async def custom_validation_exception_handler(request:Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={
            "success": False,
            "message": "Validation error",
            "errors": format_validation_errors(exc.errors()),
            "data": None
        }
    )


app.include_router(auth_router, prefix="/api/auth", tags=["Authentication"])