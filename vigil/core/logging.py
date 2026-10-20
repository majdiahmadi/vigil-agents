import logging
import re


class RedactingFilter(logging.Filter):
    patterns = (re.compile(r"(?i)(api[_-]?key|authorization|password)\s*[:=]\s*\S+"),)

    def filter(self, record: logging.LogRecord) -> bool:
        text = str(record.msg)
        for pattern in self.patterns:
            text = pattern.sub(r"\1=[REDACTED]", text)
        record.msg = text
        record.args = ()
        return True


def configure_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler()
    handler.addFilter(RedactingFilter())
    logging.basicConfig(level=level, handlers=[handler], format="%(levelname)s %(name)s %(message)s")

