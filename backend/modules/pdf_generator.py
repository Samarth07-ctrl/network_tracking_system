"""
PDF Report Generator Module

Generates a "Campus Network Security Audit" PDF report using the fpdf2 library.
The report contains:
  - Top 5 bandwidth consumers (by IP) from the last 24 hours
  - Top 5 security alerts from the last 24 hours

Design notes:
- DB query results are cached for 60 seconds to support concurrent requests
  without hammering the database.
- Both data sources accept optional override parameters so the generator can
  be called with synthetic data in tests (bypassing the DB entirely).
- Returns raw PDF bytes so the caller (FastAPI endpoint) can stream them
  directly to the browser.
"""

import io
import time
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Optional

from fpdf import FPDF

logger = logging.getLogger(__name__)


class PdfGenerationError(Exception):
    """Raised when PDF creation fails for any reason."""


# ---------------------------------------------------------------------------
# In-memory data models (never persisted)
# ---------------------------------------------------------------------------

@dataclass
class BandwidthEntry:
    """Represents a single bandwidth consumer entry in the report."""
    ip_address: str
    total_bytes: int
    percentage: float   # percentage of total traffic in the window


@dataclass
class AlertEntry:
    """Represents a single security alert entry in the report."""
    alert_type: str
    severity: str
    source_ip: str
    timestamp: datetime
    description: str


# ---------------------------------------------------------------------------
# PDF layout constants
# ---------------------------------------------------------------------------

_TITLE = "Campus Network Security Audit"
_SYSTEM_NAME = "Campus NIDS"
_PRIMARY_COLOR = (30, 64, 175)    # deep blue  (R, G, B)
_HEADER_COLOR = (239, 246, 255)   # light blue background for table headers
_ROW_ALT_COLOR = (249, 250, 251)  # very light grey for alternating rows
_CRITICAL_COLOR = (220, 38, 38)   # red for CRITICAL severity
_HIGH_COLOR = (234, 88, 12)       # orange for HIGH severity
_MEDIUM_COLOR = (202, 138, 4)     # amber for MEDIUM severity


class PdfGenerator:
    """
    Generates a security audit PDF report from database data.

    Args:
        db_manager: DatabaseManager instance used to query bandwidth and alert data.

    Example::

        generator = PdfGenerator(db_manager)
        pdf_bytes = generator.generate_report()
        # Returns raw bytes ready to stream as application/pdf
    """

    # Simple TTL cache: {cache_key: (timestamp, data)}
    _cache: dict = {}
    _CACHE_TTL_SECONDS = 60

    def __init__(self, db_manager):
        self.db_manager = db_manager

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_report(
        self,
        bandwidth_data: Optional[List[BandwidthEntry]] = None,
        alert_data: Optional[List[AlertEntry]] = None,
    ) -> bytes:
        """
        Generate the PDF security audit report.

        Args:
            bandwidth_data: Optional list of BandwidthEntry objects.  When
                provided, the DB query is skipped (useful for testing).
            alert_data: Optional list of AlertEntry objects.  When provided,
                the DB query is skipped (useful for testing).

        Returns:
            Raw PDF bytes (application/pdf).

        Raises:
            PdfGenerationError: If FPDF raises an exception or the DB query fails.
        """
        generated_at = datetime.now()

        # Fetch data (from cache / DB, or use provided override)
        if bandwidth_data is None:
            bandwidth_data = self._get_bandwidth_data()
        if alert_data is None:
            alert_data = self._get_alert_data()

        try:
            pdf = self._build_pdf(bandwidth_data, alert_data, generated_at)
            # fpdf2's output() returns bytes when dest is not specified
            return pdf.output()
        except Exception as exc:
            raise PdfGenerationError(f"PDF generation failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Data fetching (with 60-second TTL cache)
    # ------------------------------------------------------------------

    def _get_bandwidth_data(self) -> List[BandwidthEntry]:
        """
        Query the database for the top 5 bandwidth consumers.
        Uses connected_devices table sorted by total bandwidth (sent + received).
        Results are cached for 60 seconds.

        Returns:
            List of up to 5 BandwidthEntry objects sorted by total_bytes descending.
        """
        cache_key = "bandwidth"
        cached = self._read_cache(cache_key)
        if cached is not None:
            return cached

        try:
            # get_connected_devices returns devices sorted by total_bandwidth DESC
            raw = self.db_manager.get_connected_devices(active_only=False)
        except Exception as exc:
            logger.error(f"DB query failed for bandwidth data: {exc}")
            raise PdfGenerationError(f"Database error: {exc}") from exc

        # Sort by total bandwidth and take top 5
        raw_sorted = sorted(raw, key=lambda r: r.get("total_bandwidth", 0), reverse=True)[:5]

        # Calculate total bytes across all returned rows for percentage computation
        total_bytes = sum(r.get("total_bandwidth", 0) for r in raw_sorted) or 1  # avoid div-by-zero

        entries = [
            BandwidthEntry(
                ip_address=r.get("ip_address", "Unknown"),
                total_bytes=r.get("total_bandwidth", 0),
                percentage=round((r.get("total_bandwidth", 0) / total_bytes) * 100, 1),
            )
            for r in raw_sorted
        ]

        self._write_cache(cache_key, entries)
        return entries

    def _get_alert_data(self) -> List[AlertEntry]:
        """
        Query the database for the top 5 security alerts in the last 24 hours.
        Results are cached for 60 seconds.

        Returns:
            List of up to 5 AlertEntry objects sorted by timestamp descending.
        """
        cache_key = "alerts"
        cached = self._read_cache(cache_key)
        if cached is not None:
            return cached

        try:
            start_time = datetime.now() - timedelta(hours=24)
            raw = self.db_manager.get_security_alerts(
                start_time=start_time, limit=5
            )
        except Exception as exc:
            logger.error(f"DB query failed for alert data: {exc}")
            raise PdfGenerationError(f"Database error: {exc}") from exc

        entries = []
        for r in raw:
            # Build a human-readable description from the alert type and metadata
            metadata = r.get("metadata") or {}
            description = metadata.get("description") or self._build_description(r)
            ts = r.get("timestamp")
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts)
                except ValueError:
                    ts = datetime.now()

            entries.append(AlertEntry(
                alert_type=r.get("alert_type", "UNKNOWN"),
                severity=r.get("severity", "LOW"),
                source_ip=r.get("source_ip") or "N/A",
                timestamp=ts or datetime.now(),
                description=description,
            ))

        self._write_cache(cache_key, entries)
        return entries

    # ------------------------------------------------------------------
    # PDF construction
    # ------------------------------------------------------------------

    def _build_pdf(
        self,
        bandwidth_data: List[BandwidthEntry],
        alert_data: List[AlertEntry],
        generated_at: datetime,
    ) -> FPDF:
        """
        Construct the FPDF document with all sections.

        Args:
            bandwidth_data: Pre-fetched bandwidth entries.
            alert_data: Pre-fetched alert entries.
            generated_at: Timestamp to embed in the report.

        Returns:
            A fully populated FPDF instance ready for output().
        """
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=20)
        # {nb} is replaced by total page count on output
        pdf.alias_nb_pages("{nb}")
        pdf.add_page()

        # ---- Title block ----
        self._draw_title_block(pdf, generated_at)

        # ---- Section 1: Bandwidth consumers ----
        self._draw_section_header(pdf, "Top 5 Bandwidth Consumers (Last 24 Hours)")
        if bandwidth_data:
            self._draw_bandwidth_table(pdf, bandwidth_data)
        else:
            self._draw_no_data(pdf)

        pdf.ln(8)

        # ---- Section 2: Security alerts ----
        self._draw_section_header(pdf, "Top 5 Security Alerts (Last 24 Hours)")
        if alert_data:
            self._draw_alerts_table(pdf, alert_data)
        else:
            self._draw_no_data(pdf)

        return pdf

    # ------------------------------------------------------------------
    # Drawing helpers
    # ------------------------------------------------------------------

    def _draw_title_block(self, pdf: FPDF, generated_at: datetime):
        """Render the report title, subtitle, and generation timestamp."""
        # Background banner
        pdf.set_fill_color(*_PRIMARY_COLOR)
        pdf.rect(0, 0, 210, 45, style="F")

        # Title text
        pdf.set_font("Helvetica", "B", 22)
        pdf.set_text_color(255, 255, 255)
        pdf.set_xy(10, 10)
        pdf.cell(190, 12, _TITLE, align="C")

        # Subtitle
        pdf.set_font("Helvetica", "", 11)
        pdf.set_xy(10, 24)
        pdf.cell(190, 8, _SYSTEM_NAME, align="C")

        # Generation timestamp
        pdf.set_font("Helvetica", "", 9)
        pdf.set_xy(10, 34)
        pdf.cell(
            190, 6,
            f"Generated: {generated_at.strftime('%Y-%m-%d %H:%M:%S')}",
            align="C"
        )

        # Reset text colour and move below the banner
        pdf.set_text_color(0, 0, 0)
        pdf.set_xy(10, 52)

    def _draw_section_header(self, pdf: FPDF, title: str):
        """Render a coloured section header bar."""
        pdf.set_fill_color(*_PRIMARY_COLOR)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_x(10)
        pdf.cell(190, 9, f"  {title}", fill=True, ln=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(3)

    def _draw_bandwidth_table(self, pdf: FPDF, entries: List[BandwidthEntry]):
        """Render the bandwidth consumers table."""
        col_widths = [10, 70, 60, 50]   # #, IP Address, Total Data, % of Traffic
        headers = ["#", "IP Address", "Total Data Transferred", "% of Traffic"]

        # Table header row
        pdf.set_fill_color(*_HEADER_COLOR)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_x(10)
        for w, h in zip(col_widths, headers):
            pdf.cell(w, 8, h, border=1, fill=True, align="C")
        pdf.ln()

        # Data rows
        pdf.set_font("Helvetica", "", 10)
        for idx, entry in enumerate(entries, start=1):
            fill = idx % 2 == 0
            pdf.set_fill_color(*(_ROW_ALT_COLOR if fill else (255, 255, 255)))
            pdf.set_x(10)
            pdf.cell(col_widths[0], 7, str(idx), border=1, fill=fill, align="C")
            pdf.cell(col_widths[1], 7, entry.ip_address, border=1, fill=fill)
            pdf.cell(col_widths[2], 7, self._format_bytes(entry.total_bytes), border=1, fill=fill, align="R")
            pdf.cell(col_widths[3], 7, f"{entry.percentage:.1f}%", border=1, fill=fill, align="R")
            pdf.ln()

    def _draw_alerts_table(self, pdf: FPDF, entries: List[AlertEntry]):
        """Render the security alerts table."""
        col_widths = [10, 42, 22, 32, 38, 46]
        headers = ["#", "Alert Type", "Severity", "Source IP", "Timestamp", "Description"]

        # Table header row
        pdf.set_fill_color(*_HEADER_COLOR)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_x(10)
        for w, h in zip(col_widths, headers):
            pdf.cell(w, 8, h, border=1, fill=True, align="C")
        pdf.ln()

        # Data rows
        pdf.set_font("Helvetica", "", 8)
        for idx, entry in enumerate(entries, start=1):
            fill = idx % 2 == 0
            bg = _ROW_ALT_COLOR if fill else (255, 255, 255)
            pdf.set_fill_color(*bg)
            pdf.set_x(10)

            # Severity cell gets a colour-coded text
            sev_color = self._severity_color(entry.severity)

            pdf.cell(col_widths[0], 7, str(idx), border=1, fill=fill, align="C")
            pdf.cell(col_widths[1], 7, entry.alert_type.replace("_", " "), border=1, fill=fill)

            # Severity with colour
            pdf.set_text_color(*sev_color)
            pdf.cell(col_widths[2], 7, entry.severity, border=1, fill=fill, align="C")
            pdf.set_text_color(0, 0, 0)

            pdf.cell(col_widths[3], 7, entry.source_ip, border=1, fill=fill)
            pdf.cell(col_widths[4], 7, entry.timestamp.strftime("%m-%d %H:%M"), border=1, fill=fill, align="C")
            # Truncate long descriptions to fit the cell
            desc = entry.description[:38] + "…" if len(entry.description) > 38 else entry.description
            pdf.cell(col_widths[5], 7, desc, border=1, fill=fill)
            pdf.ln()

    def _draw_no_data(self, pdf: FPDF):
        """Render a 'no data available' placeholder row."""
        pdf.set_font("Helvetica", "I", 10)
        pdf.set_text_color(120, 120, 120)
        pdf.set_x(10)
        pdf.cell(190, 10, "No data available for the selected time period", align="C", border=1)
        pdf.set_text_color(0, 0, 0)
        pdf.ln()

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _format_bytes(num_bytes: int) -> str:
        """Convert a byte count to a human-readable string (KB / MB / GB)."""
        if num_bytes >= 1_073_741_824:
            return f"{num_bytes / 1_073_741_824:.2f} GB"
        if num_bytes >= 1_048_576:
            return f"{num_bytes / 1_048_576:.2f} MB"
        if num_bytes >= 1_024:
            return f"{num_bytes / 1_024:.2f} KB"
        return f"{num_bytes} B"

    @staticmethod
    def _severity_color(severity: str) -> tuple:
        """Return an RGB tuple for the given severity level."""
        mapping = {
            "CRITICAL": _CRITICAL_COLOR,
            "HIGH": _HIGH_COLOR,
            "MEDIUM": _MEDIUM_COLOR,
        }
        return mapping.get(severity.upper(), (0, 0, 0))

    @staticmethod
    def _build_description(alert: dict) -> str:
        """Build a short human-readable description from an alert dict."""
        alert_type = alert.get("alert_type", "")
        source_ip = alert.get("source_ip") or "unknown"
        descriptions = {
            "PORT_SCAN": f"Port scan from {source_ip}",
            "DDOS": f"DDoS attack targeting {alert.get('target_ip', 'unknown')}",
            "BRUTE_FORCE": f"Brute force attempt from {source_ip}",
            "PROHIBITED_WEBSITE": f"Prohibited site access by {source_ip}",
            "HIGH_BANDWIDTH": f"High bandwidth usage by {source_ip}",
            "CLEARTEXT_CREDENTIAL": f"Clear-text credentials from {source_ip}",
        }
        return descriptions.get(alert_type, f"{alert_type} from {source_ip}")

    # ------------------------------------------------------------------
    # Simple TTL cache helpers
    # ------------------------------------------------------------------

    def _read_cache(self, key: str):
        """Return cached value if it exists and has not expired, else None."""
        entry = PdfGenerator._cache.get(key)
        if entry and (time.monotonic() - entry[0]) < self._CACHE_TTL_SECONDS:
            return entry[1]
        return None

    def _write_cache(self, key: str, value):
        """Store a value in the cache with the current timestamp."""
        PdfGenerator._cache[key] = (time.monotonic(), value)
