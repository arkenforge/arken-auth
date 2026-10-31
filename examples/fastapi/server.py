from fastapi import FastAPI, Depends
from fastapi.responses import JSONResponse
from arken_auth import ArkenAuth

app = FastAPI(title="Arken Protocol — FastAPI example")


@app.get("/")
async def root():
    return {"message": "Arken Protocol — FastAPI example"}


# Protected route — requires a valid a401 signature
@app.get("/protected")
async def protected(did: str = Depends(ArkenAuth())):
    return {"message": "Authenticated", "did": did}


# Return 401 challenge as JSON (FastAPI's default raises plain text)
@app.exception_handler(401)
async def auth_exception_handler(request, exc):
    if hasattr(exc, "detail") and isinstance(exc.detail, dict):
        return JSONResponse(
            status_code=401,
            content=exc.detail,
            headers=getattr(exc, "headers", {}),
        )
    return JSONResponse(status_code=401, content={"detail": str(exc.detail)})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
