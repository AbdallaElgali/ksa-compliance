from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def get_invoices():
    return {"message": "Invoices endpoint"}

@router.get("/test")
async def test_invoices():
    return {"message": "Invoices test successful"}
