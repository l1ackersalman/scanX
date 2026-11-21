"""
`render_markdown` template filter for AI-written reports.

Report text comes from AI agents (untrusted), so the HTML that Markdown
produces is passed through nh3 with a small allow-list: no scripts, no inline
styles or event handlers, and links only to http(s)/mailto.
"""
import markdown
import nh3
from django import template
from django.utils.safestring import mark_safe

register = template.Library()

ALLOWED_TAGS = {
    "p", "br", "hr", "h1", "h2", "h3", "h4", "h5", "h6",
    "strong", "em", "b", "i", "del", "code", "pre", "blockquote",
    "ul", "ol", "li", "table", "thead", "tbody", "tr", "th", "td", "a",
}
ALLOWED_ATTRIBUTES = {"a": {"href", "title"}, "th": {"align"}, "td": {"align"}, "ol": {"start"}}


@register.filter
def render_markdown(text):
    if not text:
        return ""
    html = markdown.markdown(str(text), extensions=["tables", "fenced_code", "sane_lists"])
    clean = nh3.clean(
        html,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        url_schemes={"http", "https", "mailto"},
        link_rel="noopener noreferrer nofollow",
    )
    return mark_safe(clean)
