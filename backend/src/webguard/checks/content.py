"""Bounded static landing-page content checks."""

from __future__ import annotations

from html.parser import HTMLParser

from webguard.checks.common import finding_result
from webguard.domain.enums import FindingStatus, HttpScheme, Severity
from webguard.scanner.checks import CheckMetadata, CheckResult
from webguard.scanner.context import ResponseObservation, ScanContext, redact_observed_url

_MIXED_CONTENT_REFERENCE = (
    "https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Mixed_content"
)


def _is_html(response: ResponseObservation) -> bool:
    content_type = (response.body.content_type or "").lower()
    if "text/html" in content_type or "application/xhtml+xml" in content_type:
        return True
    prefix = response.body.content[:512].lstrip().lower()
    return prefix.startswith((b"<!doctype html", b"<html"))


class _MixedContentParser(HTMLParser):
    """Extract explicit HTTP references without loading or executing anything."""

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self._base_url = base_url
        self.references: set[tuple[str, str, str]] = set()

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        attributes = {name.lower(): value for name, value in attrs if value is not None}
        lowered_tag = tag.lower()
        attribute: str | None = None
        risk = "passive"
        if lowered_tag in {"script", "iframe"}:
            attribute = "src"
            risk = "active"
        elif lowered_tag == "form":
            attribute = "action"
            risk = "active"
        elif lowered_tag == "link":
            attribute = "href"
            rel = {token.lower() for token in attributes.get("rel", "").split()}
            risk = "active" if "stylesheet" in rel else "passive"
        elif lowered_tag in {"img", "audio", "video", "source"}:
            attribute = "src"
        if attribute is None:
            return
        raw_url = attributes.get(attribute, "").strip()
        if not raw_url.lower().startswith("http://"):
            return
        safe_url = redact_observed_url(self._base_url, raw_url)
        if safe_url == "[invalid-url]":
            return
        self.references.add((risk, lowered_tag, safe_url))


class MixedContentCheck:
    metadata = CheckMetadata(
        rule_id="content.mixed_content",
        title="Static mixed-content references",
        category="Page Content Security",
        order=300,
        references=(_MIXED_CONTENT_REFERENCE,),
    )

    def is_applicable(self, context: ScanContext) -> bool:
        response = context.landing_page
        return (
            response is not None
            and response.target.scheme is HttpScheme.HTTPS
            and _is_html(response)
        )

    def evaluate(self, context: ScanContext) -> CheckResult:
        response = context.landing_page
        if response is None:
            raise RuntimeError("Mixed-content check evaluated without a landing response")
        parser = _MixedContentParser(response.target.request_url)
        parser.feed(response.body.text)
        parser.close()
        references = sorted(parser.references)
        if not references:
            return finding_result(
                self.metadata,
                status=FindingStatus.PASS,
                description=(
                    "No explicit http:// resource reference was found in the bounded static HTML. "
                    "This check does not execute JavaScript or model all browser loading behavior."
                ),
                evidence="Explicit insecure static references detected: 0.",
                source_url=response.target.display_url,
                recommendation="Continue serving landing-page resources through HTTPS.",
            )

        active = tuple(item for item in references if item[0] == "active")
        passive = tuple(item for item in references if item[0] == "passive")
        evidence_parts: list[str] = []
        if active:
            evidence_parts.append(
                "Active/higher-risk: "
                + ", ".join(f"{tag} {url}" for _, tag, url in active[:8])
                + (f", plus {len(active) - 8} more" if len(active) > 8 else "")
                + "."
            )
        if passive:
            evidence_parts.append(
                "Passive/lower-risk: "
                + ", ".join(f"{tag} {url}" for _, tag, url in passive[:8])
                + (f", plus {len(passive) - 8} more" if len(passive) > 8 else "")
                + "."
            )
        return finding_result(
            self.metadata,
            status=FindingStatus.WARNING,
            severity=Severity.MEDIUM if active else Severity.LOW,
            description=(
                "The final HTTPS landing HTML contained explicit plaintext resource references. "
                "Active references receive greater weight than images or media, but static markup "
                "alone does not prove that a browser loaded or exploited any resource."
            ),
            evidence=" ".join(evidence_parts),
            source_url=response.target.display_url,
            recommendation="Replace required plaintext references with validated HTTPS URLs.",
        )
