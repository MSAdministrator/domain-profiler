"""Tests for the base functionality."""

import pytest
from unittest.mock import Mock, patch

from domain_profiler.base import Base


class TestBase:
    """Test cases for the Base class."""

    def test_base_class_initialization(self):
        """Test that Base class can be initialized."""
        base_instance = Base()
        assert isinstance(base_instance, Base)

    def test_base_has_extensions_attribute(self):
        """Test that Base class has extensions attribute."""
        base_instance = Base()
        assert hasattr(base_instance, 'extensions')
        assert isinstance(base_instance.extensions, list)

    def test_extensions_list_content(self):
        """Test that extensions list contains expected file extensions."""
        base_instance = Base()
        
        # Common file extensions that should be present
        expected_extensions = [
            'zip', 'exe', 'pdf', 'txt', 'log', 'bin', 'gz'
        ]
        
        for ext in expected_extensions:
            assert ext in base_instance.extensions, f"Extension '{ext}' should be in extensions list"

    def test_extensions_list_completeness(self):
        """Test that extensions list contains all expected extensions."""
        base_instance = Base()
        
        # All extensions that should be present based on the base.py file
        expected_extensions = [
            'zip', 'exe', 'msi', 'mp4', 'ps1', 'txt', 'log', 'apk', 'dll', 
            'bin', 'docx', 'tmp', 'gz', 'xlsx', 'xls', 'ppt', 'pptx', 'sh', 'pdf'
        ]
        
        assert len(base_instance.extensions) == len(expected_extensions)
        
        for ext in expected_extensions:
            assert ext in base_instance.extensions

    def test_base_uses_logging_metaclass(self):
        """Test that Base class uses LoggingBase metaclass."""
        from domain_profiler.logger import LoggingBase
        
        # Base class should use LoggingBase as metaclass
        assert isinstance(Base, LoggingBase)

    def test_base_has_logger_attribute(self):
        """Test that Base instances have logger attribute."""
        base_instance = Base()
        
        # Should have a logger attribute (name-mangled)
        logger_attr_name = f"_Base__logger"
        assert hasattr(base_instance, logger_attr_name)

    def test_extensions_are_strings(self):
        """Test that all extensions are strings."""
        base_instance = Base()
        
        for ext in base_instance.extensions:
            assert isinstance(ext, str), f"Extension '{ext}' should be a string"

    def test_extensions_no_dots(self):
        """Test that extensions don't include dots."""
        base_instance = Base()
        
        for ext in base_instance.extensions:
            assert not ext.startswith('.'), f"Extension '{ext}' should not start with dot"

    def test_extensions_lowercase(self):
        """Test that extensions are lowercase."""
        base_instance = Base()
        
        for ext in base_instance.extensions:
            assert ext.islower(), f"Extension '{ext}' should be lowercase"

    def test_base_inheritance(self):
        """Test creating a class that inherits from Base."""
        class TestDerived(Base):
            def test_method(self):
                return "test"
        
        derived_instance = TestDerived()
        
        # Should inherit extensions
        assert hasattr(derived_instance, 'extensions')
        assert len(derived_instance.extensions) > 0
        
        # Should have logger
        logger_attr_name = f"_TestDerived__logger"
        assert hasattr(derived_instance, logger_attr_name)

    def test_multiple_inheritance_scenarios(self):
        """Test Base class in multiple inheritance scenarios."""
        class Mixin:
            def mixin_method(self):
                return "mixin"
        
        class DerivedWithMixin(Base, Mixin):
            def derived_method(self):
                return "derived"
        
        instance = DerivedWithMixin()
        
        # Should have all capabilities
        assert hasattr(instance, 'extensions')
        assert hasattr(instance, 'mixin_method')
        assert hasattr(instance, 'derived_method')
        assert instance.mixin_method() == "mixin"
        assert instance.derived_method() == "derived"

    def test_extensions_immutability_consideration(self):
        """Test extensions list behavior."""
        base_instance = Base()
        original_extensions = base_instance.extensions.copy()
        
        # Test that we can access the extensions
        assert len(base_instance.extensions) > 0
        
        # Original extensions should match
        assert base_instance.extensions == original_extensions

    @pytest.mark.parametrize("extension", [
        'zip', 'exe', 'pdf', 'txt', 'log', 'bin', 'gz', 'docx', 'xlsx'
    ])
    def test_specific_extensions_present(self, extension):
        """Test that specific important extensions are present."""
        base_instance = Base()
        assert extension in base_instance.extensions

    def test_base_class_documentation(self):
        """Test that Base class has proper documentation."""
        # Base class should be importable and have meaningful structure
        assert Base.__module__ == 'domain_profiler.base'
        
        # Should have extensions as class attribute
        assert 'extensions' in Base.__dict__

    def test_logger_functionality_basic(self):
        """Test basic logger functionality through Base."""
        base_instance = Base()
        
        # Logger should be accessible
        logger_attr_name = f"_Base__logger"
        logger = getattr(base_instance, logger_attr_name)
        
        # Logger should have standard logging methods
        assert hasattr(logger, 'info')
        assert hasattr(logger, 'error')
        assert hasattr(logger, 'debug')
        assert hasattr(logger, 'warning')

    def test_base_class_as_mixin(self):
        """Test using Base as a mixin class."""
        class CustomProfiler(Base):
            def __init__(self, custom_param="default"):
                self.custom_param = custom_param
                # Base doesn't have __init__, so should work fine
            
            def custom_method(self):
                return f"Custom: {self.custom_param}"
        
        profiler = CustomProfiler("test_value")
        
        # Should have Base functionality
        assert hasattr(profiler, 'extensions')
        assert len(profiler.extensions) > 0
        
        # Should have custom functionality
        assert profiler.custom_param == "test_value"
        assert profiler.custom_method() == "Custom: test_value"

    def test_extensions_cover_security_relevant_types(self):
        """Test that extensions include security-relevant file types."""
        base_instance = Base()
        
        # Security-relevant extensions that should be monitored
        security_extensions = ['exe', 'msi', 'dll', 'bin', 'ps1', 'sh', 'apk']
        
        for ext in security_extensions:
            assert ext in base_instance.extensions, f"Security extension '{ext}' should be present" 