from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser


@dataclass(frozen=True)
class FormSummary:
    method: str
    action: str | None
    inputs: tuple[str, ...] = ()


@dataclass(frozen=True)
class HtmlSummary:
    title: str | None = None
    links: tuple[str, ...] = ()
    forms: tuple[FormSummary, ...] = ()
    has_password_input: bool = False

    def as_evidence(self) -> dict[str, object]:
        return {
            "title": self.title,
            "links": list(self.links),
            "forms": [
                {"method": form.method, "action": form.action, "inputs": list(form.inputs)}
                for form in self.forms
            ],
            "has_password_input": self.has_password_input,
        }


class HtmlStructureParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._in_title = False
        self._title_parts: list[str] = []
        self._links: list[str] = []
        self._forms: list[dict[str, object]] = []
        self._current_form: dict[str, object] | None = None
        self._has_password_input = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {name.lower(): value for name, value in attrs}
        tag = tag.lower()
        if tag == "title":
            self._in_title = True
        elif tag == "a" and attr_map.get("href"):
            self._links.append(attr_map["href"] or "")
        elif tag == "form":
            self._current_form = {
                "method": (attr_map.get("method") or "get").lower(),
                "action": attr_map.get("action"),
                "inputs": [],
            }
        elif tag == "input":
            input_type = (attr_map.get("type") or "text").lower()
            if input_type == "password":
                self._has_password_input = True
            if self._current_form is not None:
                name = attr_map.get("name") or attr_map.get("id") or input_type
                inputs = self._current_form["inputs"]
                assert isinstance(inputs, list)
                inputs.append(name)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        elif tag == "form" and self._current_form is not None:
            self._forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_parts.append(data.strip())

    def summary(self) -> HtmlSummary:
        title = " ".join(part for part in self._title_parts if part).strip() or None
        forms = tuple(
            FormSummary(
                method=str(form["method"]),
                action=form["action"] if isinstance(form["action"], str) else None,
                inputs=tuple(str(value) for value in form["inputs"]),
            )
            for form in self._forms
        )
        return HtmlSummary(
            title=title,
            links=tuple(link for link in self._links if link),
            forms=forms,
            has_password_input=self._has_password_input,
        )


def summarize_html(html: str) -> HtmlSummary:
    parser = HtmlStructureParser()
    parser.feed(html)
    parser.close()
    return parser.summary()
