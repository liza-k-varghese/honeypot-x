"""
ESP32 Hardware Security Monitoring API routes — Group 16 (Features 151-160).
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app import models, schemas
from app.api.deps import get_current_user, require_device_api_key
from app.db.postgres import get_db

router = APIRouter(prefix="/api/esp32", tags=["esp32"])

# Hardware thresholds
TEMP_HIGH_THRESHOLD_C = 45.0
SMOKE_HIGH_THRESHOLD = 400


@router.post("/readings", response_model=schemas.SensorReadingOut, dependencies=[Depends(require_device_api_key)])
def submit_sensor_reading(
    payload: schemas.SensorReadingIn,
    db: Session = Depends(get_db),
):
    """Features 151-155: Receive temperature, humidity, smoke, and tamper switch
    readings from ESP32 security sensor node."""
    alert_needed = False
    alert_reasons = []

    if payload.tamper_detected:
        alert_needed = True
        alert_reasons.append("Physical tamper detected on honeypot enclosure (reed switch open)")

    if payload.temperature_c is not None and payload.temperature_c >= TEMP_HIGH_THRESHOLD_C:
        alert_needed = True
        alert_reasons.append(f"High temperature threshold exceeded: {payload.temperature_c}°C")

    if payload.smoke_level is not None and payload.smoke_level >= SMOKE_HIGH_THRESHOLD:
        alert_needed = True
        alert_reasons.append(f"High smoke/gas level detected (MQ-2 raw value: {payload.smoke_level})")

    reading = models.SensorReading(
        device_id=payload.device_id,
        temperature_c=payload.temperature_c,
        humidity_percent=payload.humidity_percent,
        smoke_level=payload.smoke_level,
        tamper_detected=payload.tamper_detected,
        alert_triggered=alert_needed,
    )
    db.add(reading)

    if alert_needed:
        # Create hardware alert
        alert = models.Alert(
            title=f"Hardware Security Alert [{payload.device_id}]",
            description="; ".join(alert_reasons),
            severity="critical" if payload.tamper_detected else "high",
            source="esp32_hardware_sensor",
            status="open",
        )
        db.add(alert)

    db.commit()
    db.refresh(reading)
    return reading


@router.get("/readings", response_model=list[schemas.SensorReadingOut])
def list_sensor_readings(
    limit: int = Query(50, le=500),
    device_id: str | None = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """List historical ESP32 sensor readings."""
    query = db.query(models.SensorReading)
    if device_id:
        query = query.filter(models.SensorReading.device_id == device_id)
    return query.order_by(models.SensorReading.recorded_at.desc()).limit(limit).all()


@router.get("/latest", response_model=schemas.SensorReadingOut)
def get_latest_sensor_reading(
    device_id: str = "esp32-01",
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Get the most recent reading from an ESP32 sensor device."""
    reading = (
        db.query(models.SensorReading)
        .filter(models.SensorReading.device_id == device_id)
        .order_by(models.SensorReading.recorded_at.desc())
        .first()
    )
    if reading is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No readings found for this device")
    return reading
