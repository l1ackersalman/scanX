"""
No-cache middleware for scanX.

Prevents browsers from caching HTML responses so users always see
the latest scan status and results without stale-cache issues.
"""


class NoCacheMiddleware:
    """
    Adds Cache-Control headers to all responses to prevent browser caching.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Only apply to HTML responses (text/html content type)
        content_type = response.get("Content-Type", "")
        if "text/html" in content_type:
            response["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
            response["Pragma"] = "no-cache"
            response["Expires"] = "0"

        return response