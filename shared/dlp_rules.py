"""
DLP Rules Engine v2.0 — Контекстный анализ ДСП

Принцип: данные → кандидаты → контекст → комбинации → score → решение

Ключевые отличия от v1:
  - ФИО одно ≠ ДСП. ФИО + телефон = ДСП. ФИО + паспорт = ДСП.
  - Гриф ("для служебного пользования") = всегда ДСП.
  - Score-система: каждый тип данных даёт баллы, порог = блокировка.
  - Контекстное окно: 500 символов вокруг найденного.
  - Валидация: ИНН проверяется контрольной суммой, карта — Luhn.
"""

import re
import json
import logging
from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path

logger = logging.getLogger("dlp.rules")

# ══════════════════════════════════════════════════════════════════════════════
# Конфигурация
# ══════════════════════════════════════════════════════════════════════════════

# Score threshold: если суммарный score >= этого значения → флаг/блокировка
SCORE_THRESHOLD = 80

# ── Whitelist / Skip ─────────────────────────────────────────────────────────
WHITELIST_DOMAINS = {
    "yandex.ru", "ya.ru", "google.com", "google.ru", "bing.com",
    "suggest.yandex.ru", "yandex.net", "yastatic.net",
    "msn.com", "microsoft.com", "windowsupdate.com",
    "edge.microsoft.com", "msftconnecttest.com",
    "ctldl.windowsupdate.com", "ocsp.digicert.com",
    "ntp.msn.com", "browser.events.data.msn.com",
    "login.live.com", "live.com", "go.microsoft.com",
}

SKIP_CONTENT_TYPES = {
    "image/", "audio/", "video/", "font/",
    "application/javascript", "application/x-javascript",
    "text/javascript", "text/css",
    "application/octet-stream",
}


# ══════════════════════════════════════════════════════════════════════════════
# Детекторы (кандидаты)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Candidate:
    """Найденный кандидат на ДСП-данные"""
    type: str           # FULL_NAME, PHONE, INN, SNILS, CARD, PASSPORT, etc.
    value: str          # найденное значение
    position: int       # позиция в тексте
    score: int          # базовые баллы
    severity: str       # LOW / MEDIUM / HIGH
    description: str    # описание
    validated: bool = True  # прошёл ли валидацию (Luhn, контр. сумма)


# ── Regex-паттерны ───────────────────────────────────────────────────────────

_PATTERNS = {
    # Гриф ДСП — полные фразы (HIGH, всегда блокирует)
    "DSP_PHRASE": (
        r"(?:для\s+служебного\s+пользования|совершенно\s+секретно|"
        r"не\s+для\s+распространения|служебная\s+тайна|"
        r"коммерческая\s+тайна|государственная\s+тайна|"
        r"strictly\s+confidential|top\s+secret|not\s+for\s+distribution|"
        r"конфиденциально|ограниченного\s+доступа|"
        r"только\s+для\s+внутреннего\s+использования)",
        150, "HIGH", "Гриф конфиденциальности"
    ),

    # Паспорт с контекстом (слово "паспорт" рядом)
    "PASSPORT_FULL": (
        r"(?:паспорт|серия|passport)\s*[:\-–]?\s*(\d{2})\s?(\d{2})\s?(\d{6})",
        80, "HIGH", "Паспорт РФ (серия + номер)"
    ),

    # СНИЛС (формат XXX-XXX-XXX XX)
    "SNILS": (
        r"\b(\d{3})-(\d{3})-(\d{3})\s?(\d{2})\b",
        80, "HIGH", "СНИЛС"
    ),

    # ИНН с контекстным словом
    "INN_CTX": (
        r"(?:инн|ИНН)\s*[:\-–]?\s*(\d{10}|\d{12})\b",
        70, "HIGH", "ИНН (с маркером)"
    ),

    # ИНН без контекста — только число (нужна валидация)
    "INN_BARE": (
        r"\b(\d{10}|\d{12})\b",
        20, "LOW", "Число похожее на ИНН"
    ),

    # Банковская карта (4 группы по 4 цифры)
    "CARD": (
        r"\b(\d{4})[\s\-](\d{4})[\s\-](\d{4})[\s\-](\d{4})\b",
        90, "HIGH", "Номер банковской карты"
    ),

    # Телефон РФ
    "PHONE": (
        r"(?:\+7|8)[\s\-]?\(?(\d{3})\)?[\s\-]?(\d{3})[\s\-]?(\d{2})[\s\-]?(\d{2})",
        15, "LOW", "Телефон РФ"
    ),

    # Email
    "EMAIL": (
        r"\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b",
        10, "LOW", "Email"
    ),

    # ФИО (три слова с заглавной кириллической буквы)
    "FULL_NAME": (
        r"\b([А-ЯЁ][а-яё]{1,20})\s+([А-ЯЁ][а-яё]{1,20})\s+"
        r"([А-ЯЁ][а-яё]{1,20}(?:ич|на|вна|евна|овна|ьич|еевич|ёвич)?)\b",
        15, "LOW", "ФИО"
    ),

    # Домашний адрес
    "ADDRESS": (
        r"(?:ул\.?|улица|пр\.?|проспект|пер\.?|переулок|бульвар|пл\.?|площадь)"
        r"\s+[А-ЯЁа-яё\w\s\-]{2,30},?\s*д\.?\s*\d+",
        25, "MEDIUM", "Почтовый адрес"
    ),

    # Банковский счёт (20 цифр) — только с контекстом
    "BANK_ACCOUNT": (
        r"\b(\d{20})\b",
        15, "LOW", "20-значное число (возможно счёт)"
    ),

    # Дата рождения (ДД.ММ.ГГГГ с маркером)
    "BIRTH_DATE": (
        r"(?:дата\s+рождения|д\.?\s*р\.?|born)\s*[:\-–]?\s*"
        r"(\d{2})[.\-/](\d{2})[.\-/](\d{4})",
        30, "MEDIUM", "Дата рождения"
    ),
}

# Скомпилированные паттерны
_COMPILED = {}
for name, (pattern, score, severity, desc) in _PATTERNS.items():
    try:
        _COMPILED[name] = re.compile(pattern, re.IGNORECASE | re.UNICODE)
    except re.error as e:
        logger.error(f"[DLP] Ошибка компиляции {name}: {e}")


# ── Слова-исключения для ФИО (фильтрация мусора) ────────────────────────────
# Если все три слова ФИО — это просто заголовки/города, не считать за ФИО
_FIO_EXCLUDE_WORDS = {
    "российская", "федерация", "республика", "область", "край",
    "город", "район", "улица", "проспект", "россия", "москва",
    "санкт", "петербург", "нижний", "новгород", "красная", "площадь",
    "министерство", "управление", "департамент", "отделение",
    "утверждаю", "согласовано", "приложение", "контактная", "информация",
}


# ══════════════════════════════════════════════════════════════════════════════
# Валидация
# ══════════════════════════════════════════════════════════════════════════════

def _luhn_check(number: str) -> bool:
    """Алгоритм Луна для номера карты"""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) != 16:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _inn_check(number: str) -> bool:
    """Проверка контрольной суммы ИНН"""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) == 10:
        weights = [2, 4, 10, 3, 5, 9, 4, 6, 8]
        control = sum(d * w for d, w in zip(digits[:9], weights)) % 11 % 10
        return control == digits[9]
    elif len(digits) == 12:
        w1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        w2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        c1 = sum(d * w for d, w in zip(digits[:10], w1)) % 11 % 10
        c2 = sum(d * w for d, w in zip(digits[:11], w2)) % 11 % 10
        return c1 == digits[10] and c2 == digits[11]
    return False


def _validate_fio(word1: str, word2: str, word3: str) -> bool:
    """Проверить что три слова — реальное ФИО, а не мусор"""
    words_lower = {word1.lower(), word2.lower(), word3.lower()}
    # Если хотя бы два слова — из списка исключений
    overlap = words_lower & _FIO_EXCLUDE_WORDS
    if len(overlap) >= 2:
        return False
    # Слишком короткие слова (2 символа) — скорее всего не ФИО
    if len(word1) < 3 or len(word2) < 3 or len(word3) < 3:
        return False
    return True


# ══════════════════════════════════════════════════════════════════════════════
# Контекстный анализ
# ══════════════════════════════════════════════════════════════════════════════

# Маркеры персональных данных в контексте
_PD_CONTEXT = {
    "фамилия", "имя", "отчество", "фио", "ф.и.о",
    "паспорт", "серия", "номер", "выдан", "дата рождения",
    "место рождения", "прописка", "регистрация", "адрес",
    "снилс", "инн", "полис", "страховой", "свидетельство",
    "работник", "сотрудник", "гражданин", "заявитель",
}

# Маркеры финансовых данных
_FIN_CONTEXT = {
    "расчётный", "расчетный", "р/с", "к/с", "корреспондентский",
    "бик", "инн", "кпп", "огрн", "реквизиты", "банк", "счёт", "счет",
    "перевод", "оплата", "платёж", "баланс",
}

# Маркеры конфиденциальности в контексте ДСП
_DSP_CONTEXT = {
    "гриф", "документ", "дело", "сведения", "информация",
    "отчёт", "отчет", "справка", "служебный", "пользования",
    "ограниченного", "доступа", "секрет", "classified", "confidential",
}

# Маркеры строительных материалов (ДСП ≠ гриф)
_DSP_MATERIAL = {
    "плита", "стружечная", "древесно", "мебель", "ламинир",
    "лдсп", "мдф", "купить", "цена", "доставка", "толщина",
}

CONTEXT_RADIUS = 500  # символов вокруг найденного


def _get_context(text: str, pos: int, radius: int = CONTEXT_RADIUS) -> str:
    """Извлечь контекстное окно вокруг позиции"""
    start = max(0, pos - radius)
    end = min(len(text), pos + radius)
    return text[start:end].lower()


def _has_context_words(context: str, word_set: set) -> list[str]:
    """Найти маркерные слова в контексте, вернуть список найденных"""
    found = []
    for w in word_set:
        if w in context:
            found.append(w)
    return found


# ══════════════════════════════════════════════════════════════════════════════
# Комбинации (главная логика)
# ══════════════════════════════════════════════════════════════════════════════

# Какие типы данных усиливают друг друга
COMBINATIONS = {
    # (тип1, тип2) → бонус к score
    ("FULL_NAME", "PHONE"):      60,
    ("FULL_NAME", "EMAIL"):      60,
    ("FULL_NAME", "PASSPORT_FULL"): 80,
    ("FULL_NAME", "SNILS"):      80,
    ("FULL_NAME", "INN_CTX"):    70,
    ("FULL_NAME", "CARD"):       80,
    ("FULL_NAME", "ADDRESS"):    50,
    ("FULL_NAME", "BIRTH_DATE"): 60,
    ("PHONE", "ADDRESS"):        40,
    ("PHONE", "PASSPORT_FULL"):  60,
    ("PHONE", "SNILS"):          60,
    ("INN_CTX", "BANK_ACCOUNT"): 60,
    ("SNILS", "BIRTH_DATE"):     60,
    ("ADDRESS", "PASSPORT_FULL"):60,
}


# ══════════════════════════════════════════════════════════════════════════════
# Главный движок
# ══════════════════════════════════════════════════════════════════════════════

class DLPEngine:
    """
    DLP Engine v2.0 — контекстный анализ

    Принцип работы:
    1. Сканирование текста regex-паттернами → кандидаты
    2. Валидация (ИНН контрольная сумма, карта Luhn, ФИО фильтр)
    3. Контекстный анализ (что рядом с находкой?)
    4. Комбинации (ФИО + телефон → высокий риск)
    5. Score → решение (block / monitor / pass)
    """

    def __init__(self, rules=None, config: dict = None):
        self.config = config or {}
        self.blocked_domains: set = set(self.config.get("blocked_domains", []))
        self.allowed_domains: set = set(self.config.get("allowed_domains", []))
        self.score_threshold = self.config.get("score_threshold", SCORE_THRESHOLD)

        # Для совместимости с v1
        self.rules = list(_PATTERNS.keys())

        logger.info(
            f"[DLPEngine] v2.0 инициализирован | "
            f"детекторов: {len(_PATTERNS)} | порог: {self.score_threshold}"
        )

    # ── Domain checks ────────────────────────────────────────────────────────

    def is_whitelisted_domain(self, host: str) -> bool:
        host = host.lower().strip()
        for d in self.allowed_domains:
            if host == d or host.endswith("." + d):
                return True
        for d in WHITELIST_DOMAINS:
            if host == d or host.endswith("." + d):
                return True
        return False

    def is_blocked_domain(self, host: str) -> bool:
        host = host.lower().strip()
        for d in self.blocked_domains:
            if host == d or host.endswith("." + d):
                return True
        return False

    def should_skip_content_type(self, ct: str) -> bool:
        ct = ct.lower()
        return any(ct.startswith(s) for s in SKIP_CONTENT_TYPES)

    # ── Text extraction layers ───────────────────────────────────────────────

    def _extract_layers(self, text: str, content_type: str) -> list[str]:
        layers = [text]
        if "json" in content_type.lower():
            try:
                obj = json.loads(text)
                parts = []
                def _walk(o):
                    if isinstance(o, str): parts.append(o)
                    elif isinstance(o, dict):
                        for v in o.values(): _walk(v)
                    elif isinstance(o, list):
                        for v in o: _walk(v)
                _walk(obj)
                if parts:
                    layers.append("\n".join(parts))
            except Exception:
                pass
        return layers

    # ── Step 1: Find candidates ──────────────────────────────────────────────

    def _find_candidates(self, text: str) -> list[Candidate]:
        candidates = []

        for name, (pattern_str, base_score, severity, desc) in _PATTERNS.items():
            compiled = _COMPILED.get(name)
            if not compiled:
                continue

            matches = list(compiled.finditer(text))

            # Limit for performance
            if name == "FULL_NAME":
                matches = matches[:20]  # Макс 20 ФИО
            elif name in ("INN_BARE", "BANK_ACCOUNT"):
                matches = matches[:10]  # Макс 10 чисел
            else:
                matches = matches[:50]

            for m in matches:
                value = m.group()
                pos = m.start()

                # ── Step 2: Validate ─────────────────────────────────────────
                validated = True

                if name == "CARD":
                    digits = re.sub(r'\D', '', value)
                    validated = _luhn_check(digits)
                    if not validated:
                        continue

                elif name == "INN_CTX":
                    inn_match = re.search(r'\d{10,12}', value)
                    if inn_match:
                        validated = _inn_check(inn_match.group())
                    if not validated:
                        continue

                elif name == "INN_BARE":
                    validated = _inn_check(value.strip())
                    if not validated:
                        continue
                    # Bare INN needs financial context
                    ctx = _get_context(text, pos, 200)
                    if not _has_context_words(ctx, _FIN_CONTEXT | _PD_CONTEXT):
                        continue

                elif name == "FULL_NAME":
                    groups = m.groups()
                    if len(groups) >= 3:
                        validated = _validate_fio(groups[0], groups[1], groups[2])
                    if not validated:
                        continue

                elif name == "BANK_ACCOUNT":
                    ctx = _get_context(text, pos, 200)
                    if not _has_context_words(ctx, _FIN_CONTEXT):
                        continue

                candidates.append(Candidate(
                    type=name, value=value[:80], position=pos,
                    score=base_score, severity=severity,
                    description=desc, validated=validated,
                ))

        return candidates

    # ── Step 3: Context enhancement ──────────────────────────────────────────

    def _enhance_with_context(self, text: str,
                               candidates: list[Candidate]) -> list[Candidate]:
        """Повысить score кандидатов если рядом есть маркерные слова"""
        for c in candidates:
            ctx = _get_context(text, c.position)

            # ПДн-контекст повышает score идентификаторов
            if c.type in ("SNILS", "PASSPORT_FULL", "INN_CTX", "CARD"):
                pd_words = _has_context_words(ctx, _PD_CONTEXT)
                if pd_words:
                    c.score += 20
                    c.severity = "HIGH"

            # Финансовый контекст повышает score банковских данных
            if c.type in ("BANK_ACCOUNT", "INN_BARE"):
                fin_words = _has_context_words(ctx, _FIN_CONTEXT)
                if fin_words:
                    c.score += 30

            # ДСП-контекст для коротких ключевых слов
            if c.type == "DSP_PHRASE":
                # Проверяем что это не ДСП-плита
                mat_words = _has_context_words(ctx, _DSP_MATERIAL)
                if mat_words:
                    c.score = 0  # обнулить — это мебель
                    c.severity = "LOW"

        return candidates

    # ── Step 4: Combination bonuses ──────────────────────────────────────────

    def _apply_combinations(self,
                            candidates: list[Candidate]) -> tuple[int, list[str]]:
        """Вычислить бонусный score от комбинаций"""
        types_found = {c.type for c in candidates if c.score > 0}
        bonus = 0
        reasons = []

        for (t1, t2), combo_score in COMBINATIONS.items():
            if t1 in types_found and t2 in types_found:
                bonus += combo_score
                reasons.append(f"{t1}+{t2}")

        return bonus, reasons

    # ── Main analysis ────────────────────────────────────────────────────────

    def analyze(self, text: str, source_info: str = "",
                content_type: str = "") -> list[dict]:
        """Полный анализ текста. Возвращает список совпадений."""
        if not text or len(text) < 5:
            return []

        layers = self._extract_layers(text, content_type)
        all_candidates: list[Candidate] = []
        seen_types: set = set()

        for layer in layers:
            candidates = self._find_candidates(layer)
            candidates = self._enhance_with_context(layer, candidates)

            for c in candidates:
                if c.type not in seen_types or c.type == "FULL_NAME":
                    all_candidates.append(c)
                    seen_types.add(c.type)

        if not all_candidates:
            return []

        # Deduplicate FIOs — keep max 3
        fio_candidates = [c for c in all_candidates if c.type == "FULL_NAME"]
        other_candidates = [c for c in all_candidates if c.type != "FULL_NAME"]
        all_candidates = other_candidates + fio_candidates[:3]

        # Combination bonus
        combo_bonus, combo_reasons = self._apply_combinations(all_candidates)

        # Total score
        base_score = sum(c.score for c in all_candidates)
        total_score = base_score + combo_bonus

        # Build results
        results = []
        for c in all_candidates:
            if c.score <= 0:
                continue
            results.append({
                "rule": c.type,
                "description": c.description,
                "severity": c.severity,
                "score": c.score,
                "count": 1,
                "source": source_info,
                "sample": c.value[:60],
                "positions": [c.position],
            })

        if combo_reasons:
            logger.info(
                f"[DLP] Комбинации: {', '.join(combo_reasons)} "
                f"(+{combo_bonus} баллов)"
            )

        # Upgrade severity based on total score
        if total_score >= self.score_threshold:
            for r in results:
                if r["severity"] != "HIGH":
                    r["severity"] = "HIGH"
                    r["description"] += " [в комбинации]"

        logger.info(
            f"[DLP] Анализ {source_info}: "
            f"кандидатов={len(all_candidates)} "
            f"score={base_score}+{combo_bonus}={total_score} "
            f"порог={self.score_threshold}"
        )

        return results

    # ── Decision ─────────────────────────────────────────────────────────────

    def should_block(self, text: str, source_info: str = "",
                     host: str = "",
                     content_type: str = "") -> tuple[bool, list[dict]]:
        """Returns (should_flag, matches)"""
        if host and self.is_whitelisted_domain(host):
            return False, []

        matches = self.analyze(text, source_info, content_type)
        if not matches:
            return False, matches

        total_score = sum(m.get("score", 0) for m in matches)

        # Check combinations
        types = {m["rule"] for m in matches}
        for (t1, t2), bonus in COMBINATIONS.items():
            if t1 in types and t2 in types:
                total_score += bonus

        should_flag = total_score >= self.score_threshold

        if should_flag:
            high_rules = [m["rule"] for m in matches if m["severity"] == "HIGH"]
            logger.warning(
                f"[DLP] ФЛАГ {source_info}: score={total_score} "
                f"правила: {high_rules}"
            )

        return should_flag, matches
