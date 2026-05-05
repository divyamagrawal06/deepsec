from fastapi import APIRouter, FastAPI

app = FastAPI()
router = APIRouter()


@app.get("/status")
async def status():
    return {"ok": True}


@router.post("/users")
def create_user(payload: dict):
    return payload


@router.api_route("/reports", methods=["GET", "POST"])
async def reports():
    return []
