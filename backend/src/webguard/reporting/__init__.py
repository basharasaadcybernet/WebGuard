"""Pure JSON and HTML reporting over public WebGuard scan contracts."""

from webguard.reporting.builder import ReportBuilder, reportable_findings
from webguard.reporting.files import ReportWriteError, validate_new_report_path, write_new_report
from webguard.reporting.html_report import HtmlReportRenderer, HtmlReportTheme
from webguard.reporting.json_report import JsonReportRenderer
from webguard.reporting.models import REPORT_SCHEMA_VERSION, ReportDocument, SeverityCount

__all__ = [
    "REPORT_SCHEMA_VERSION",
    "HtmlReportRenderer",
    "HtmlReportTheme",
    "JsonReportRenderer",
    "ReportBuilder",
    "ReportDocument",
    "ReportWriteError",
    "SeverityCount",
    "reportable_findings",
    "validate_new_report_path",
    "write_new_report",
]
