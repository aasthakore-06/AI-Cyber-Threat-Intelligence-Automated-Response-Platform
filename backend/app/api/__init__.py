from fastapi import APIRouter, Depends
from app.core.security import get_current_admin
from app.api.health import router as health_router
from app.api.auth import router as auth_router
from app.api.events import router as events_router
from app.api.alerts import router as alerts_router
from app.api.incidents import router as incidents_router
from app.api.stats import router as stats_router
from app.api.upload import router as upload_router
from app.api.honeytoken import router as honeytoken_router, public_router as honeytoken_webhook_router
from app.api.settings import router as settings_router

api_router = APIRouter()

# open routes: health check, login, honeytoken webhook (decoys call it, no token)
api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(honeytoken_webhook_router)

# everything else needs the admin JWT
protected = [Depends(get_current_admin)]
for r in (events_router, alerts_router, incidents_router, stats_router,
          upload_router, settings_router, honeytoken_router):
    api_router.include_router(r, dependencies=protected)
