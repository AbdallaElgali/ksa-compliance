from fastapi import FastAPI
from routers import onboarding, invoices

app = FastAPI(
    title="Starter FastAPI App",
    description="A starter FastAPI project with onboarding and invoices routers",
    version="1.0.0",
    debug=True
)

# Include routers
app.include_router(onboarding.router, prefix="/onboarding", tags=["Onboarding"])
app.include_router(invoices.router, prefix="/invoices", tags=["Invoices"])

@app.get("/")
async def root():
    return {"message": "Welcome to the Starter FastAPI app"}
