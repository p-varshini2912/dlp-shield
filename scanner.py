# scanner.py
# Presidio wrapper - detects + redacts PII from raw text.

from typing import List, Dict, Any

from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig


class ScanError(Exception):
    pass


class DLPScanner:

    ENTITIES = [
        "PHONE_NUMBER",
        "EMAIL_ADDRESS",
        "CREDIT_CARD",
        "ENTERPRISE_ASSET_ID",
        "ACCOUNT_REFERENCE_ID",
        "US_SSN",
        "API_SECRET_KEY",
    ]

    def __init__(self):
        try:
            provider = NlpEngineProvider(nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
            })
            nlp_engine = provider.create_engine()

            self.analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
            self.anonymizer = AnonymizerEngine()
        except Exception as e:
            raise ScanError(f"couldn't start presidio engines: {e}")

        self._add_asset_id_recognizer()
        self._add_backup_phone_recognizer()
        self._add_account_reference_recognizer()
        self._add_backup_credit_card_recognizer()
        self._add_api_secret_key_recognizer()
        self._add_backup_ssn_recognizer()

    def _add_asset_id_recognizer(self):
        pattern = Pattern(
            name="asset_id_pattern",
            regex=r"\b[A-Z]{2,10}-(?:ID|KEY)-\d{5}\b",
            score=0.9,
        )
        recognizer = PatternRecognizer(
            supported_entity="ENTERPRISE_ASSET_ID",
            patterns=[pattern],
            context=["asset", "corp", "secure", "key", "id"],
        )
        try:
            self.analyzer.registry.add_recognizer(recognizer)
        except Exception as e:
            raise ScanError(f"failed registering custom recognizer: {e}")

    def _add_backup_phone_recognizer(self):
        pattern = Pattern(
            name="backup_phone_pattern",
            regex=r"\+\d{1,3}[-\s]?\d{2,4}[-\s]?\d{3,4}[-\s]?\d{3,4}",
            score=0.75,
        )
        recognizer = PatternRecognizer(
            supported_entity="PHONE_NUMBER",
            patterns=[pattern],
            context=["phone", "call", "contact", "reach", "mobile", "number"],
        )
        try:
            self.analyzer.registry.add_recognizer(recognizer)
        except Exception as e:
            raise ScanError(f"failed registering backup phone recognizer: {e}")

    def _add_account_reference_recognizer(self):
        pattern = Pattern(
            name="account_reference_pattern",
            regex=r"\b[A-Z]{2,10}-[A-Z]{2,10}-\d{4}-\d{4}\b",
            score=0.85,
        )
        recognizer = PatternRecognizer(
            supported_entity="ACCOUNT_REFERENCE_ID",
            patterns=[pattern],
            context=["account", "reference", "id", "ref", "file"],
        )
        try:
            self.analyzer.registry.add_recognizer(recognizer)
        except Exception as e:
            raise ScanError(f"failed registering account reference recognizer: {e}")

    def _add_backup_credit_card_recognizer(self):
        pattern = Pattern(
            name="backup_credit_card_pattern",
            regex=r"\b\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}\b",
            score=0.8,
        )
        recognizer = PatternRecognizer(
            supported_entity="CREDIT_CARD",
            patterns=[pattern],
            context=["card", "credit", "payment", "visa", "mastercard"],
        )
        try:
            self.analyzer.registry.add_recognizer(recognizer)
        except Exception as e:
            raise ScanError(f"failed registering backup credit card recognizer: {e}")

    def _add_api_secret_key_recognizer(self):
        pattern = Pattern(
            name="api_secret_key_pattern",
            regex=r"\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b",
            score=0.9,
        )
        recognizer = PatternRecognizer(
            supported_entity="API_SECRET_KEY",
            patterns=[pattern],
            context=["api", "token", "secret", "key", "bearer", "authorization"],
        )
        try:
            self.analyzer.registry.add_recognizer(recognizer)
        except Exception as e:
            raise ScanError(f"failed registering api secret key recognizer: {e}")

    def _add_backup_ssn_recognizer(self):
        # explicit, high-confidence SSN pattern - bypasses Presidio's
        # built-in weak-signal SSN recognizer which needs specific context
        # wording to score high enough to surface
        pattern = Pattern(
            name="backup_ssn_pattern",
            regex=r"\b\d{3}-\d{2}-\d{4}\b",
            score=0.85,
        )
        recognizer = PatternRecognizer(
            supported_entity="US_SSN",
            patterns=[pattern],
            context=["ssn", "social", "security", "identity"],
        )
        try:
            self.analyzer.registry.add_recognizer(recognizer)
        except Exception as e:
            raise ScanError(f"failed registering backup ssn recognizer: {e}")

    def analyze(self, text: str) -> List[Any]:
        if not text:
            return []
        try:
            return self.analyzer.analyze(text=text, entities=self.ENTITIES, language="en")
        except Exception as e:
            raise ScanError(f"analysis blew up: {e}")

    def redact(self, text: str, results: List[Any]) -> str:
        if not results:
            return text

        ops = {
            "DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED]"}),
            "ENTERPRISE_ASSET_ID": OperatorConfig("replace", {"new_value": "[REDACTED-ASSET-ID]"}),
            "ACCOUNT_REFERENCE_ID": OperatorConfig("replace", {"new_value": "[REDACTED-ACCOUNT-ID]"}),
            "API_SECRET_KEY": OperatorConfig("replace", {"new_value": "[REDACTED-API-KEY]"}),
            "US_SSN": OperatorConfig("replace", {"new_value": "[REDACTED-SSN]"}),
        }

        try:
            out = self.anonymizer.anonymize(text=text, analyzer_results=results, operators=ops)
            return out.text
        except Exception as e:
            raise ScanError(f"anonymize step failed: {e}")

    def scan(self, text: str) -> Dict[str, Any]:
        results = self.analyze(text)
        redacted = self.redact(text, results)
        types_found = sorted(set(r.entity_type for r in results))
        return {
            "redacted_text": redacted,
            "hits": len(results),
            "entity_types": types_found,
        }


scanner = DLPScanner()
