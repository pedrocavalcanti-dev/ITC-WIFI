from django.test.runner import DiscoverRunner


class ProjectTestRunner(DiscoverRunner):
    """Descobrir apps locais mesmo quando gerenciar.py é chamado da raiz."""

    def build_suite(self, test_labels=None, **kwargs):
        return super().build_suite(test_labels or ["apps"], **kwargs)
