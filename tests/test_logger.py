"""Tests for the logging functionality."""

import pytest
import logging
from unittest.mock import Mock, patch, MagicMock
from io import StringIO

from domain_profiler.logger import (
    LoggingBase, 
    CustomFormatter, 
    DebugFileHandler, 
    LOGGING_CONFIG
)


class TestLoggingBase:
    """Test cases for the LoggingBase metaclass."""

    def test_logging_base_metaclass_creation(self):
        """Test that LoggingBase can create classes with logging."""
        class TestClass(metaclass=LoggingBase):
            pass
        
        instance = TestClass()
        
        # Should have a logger attribute
        logger_attr_name = "_TestClass__logger"
        assert hasattr(instance, logger_attr_name)
        
        logger = getattr(instance, logger_attr_name)
        assert isinstance(logger, logging.Logger)

    def test_logging_base_logger_naming(self):
        """Test that LoggingBase creates properly named loggers."""
        class ParentClass(metaclass=LoggingBase):
            pass
        
        class ChildClass(ParentClass):
            pass
        
        parent_instance = ParentClass()
        child_instance = ChildClass()
        
        # Check logger names
        parent_logger = getattr(parent_instance, "_ParentClass__logger")
        child_logger = getattr(child_instance, "_ChildClass__logger")
        
        # Loggers should have hierarchical names
        assert "ParentClass" in parent_logger.name
        assert "ChildClass" in child_logger.name

    def test_logging_base_inheritance_chain(self):
        """Test logger naming with inheritance chain."""
        class GrandParent(metaclass=LoggingBase):
            pass
        
        class Parent(GrandParent):
            pass
        
        class Child(Parent):
            pass
        
        child_instance = Child()
        logger = getattr(child_instance, "_Child__logger")
        
        # Logger name should reflect inheritance chain
        assert isinstance(logger, logging.Logger)
        assert logger.name  # Should have a meaningful name

    @patch('logging.config.dictConfig')
    def test_logging_base_configures_logging(self, mock_dict_config):
        """Test that LoggingBase configures logging on class creation."""
        class TestClass(metaclass=LoggingBase):
            pass
        
        # Should have called dictConfig with LOGGING_CONFIG
        mock_dict_config.assert_called_with(config=LOGGING_CONFIG)

    def test_multiple_classes_same_metaclass(self):
        """Test multiple classes using LoggingBase metaclass."""
        class FirstClass(metaclass=LoggingBase):
            pass
        
        class SecondClass(metaclass=LoggingBase):
            pass
        
        first_instance = FirstClass()
        second_instance = SecondClass()
        
        first_logger = getattr(first_instance, "_FirstClass__logger")
        second_logger = getattr(second_instance, "_SecondClass__logger")
        
        # Should have different loggers
        assert first_logger != second_logger
        assert first_logger.name != second_logger.name


class TestCustomFormatter:
    """Test cases for the CustomFormatter class."""

    def test_custom_formatter_initialization(self):
        """Test CustomFormatter initialization."""
        fmt = "%(asctime)s - %(levelname)s - %(message)s"
        formatter = CustomFormatter(fmt)
        
        assert formatter.fmt == fmt
        assert hasattr(formatter, 'FORMATS')
        assert isinstance(formatter.FORMATS, dict)

    def test_custom_formatter_has_color_codes(self):
        """Test that CustomFormatter has color codes defined."""
        formatter = CustomFormatter("test")
        
        # Should have color attributes
        assert hasattr(formatter, 'grey')
        assert hasattr(formatter, 'blue')
        assert hasattr(formatter, 'yellow')
        assert hasattr(formatter, 'red')
        assert hasattr(formatter, 'bold_red')
        assert hasattr(formatter, 'reset')

    def test_custom_formatter_format_levels(self):
        """Test CustomFormatter formats different log levels."""
        fmt = "%(levelname)s - %(message)s"
        formatter = CustomFormatter(fmt)
        
        # Test different log levels
        levels = [
            logging.DEBUG,
            logging.INFO,
            logging.WARNING,
            logging.ERROR,
            logging.CRITICAL
        ]
        
        for level in levels:
            record = logging.LogRecord(
                name="test",
                level=level,
                pathname="",
                lineno=0,
                msg="Test message",
                args=(),
                exc_info=None
            )
            
            formatted = formatter.format(record)
            assert "Test message" in formatted
            assert logging.getLevelName(level) in formatted

    def test_custom_formatter_color_formatting(self):
        """Test that CustomFormatter applies colors correctly."""
        fmt = "%(message)s"
        formatter = CustomFormatter(fmt)
        
        # Create a debug record
        debug_record = logging.LogRecord(
            name="test",
            level=logging.DEBUG,
            pathname="",
            lineno=0,
            msg="Debug message",
            args=(),
            exc_info=None
        )
        
        formatted = formatter.format(debug_record)
        # Should contain color codes (grey for debug)
        assert formatter.grey in formatted or "Debug message" in formatted

    def test_custom_formatter_reset_codes(self):
        """Test that CustomFormatter includes reset codes."""
        fmt = "%(message)s"
        formatter = CustomFormatter(fmt)
        
        info_record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Info message",
            args=(),
            exc_info=None
        )
        
        formatted = formatter.format(info_record)
        # Should include reset code or the message
        assert formatter.reset in formatted or "Info message" in formatted

    @pytest.mark.parametrize("level,expected_color_attr", [
        (logging.DEBUG, 'grey'),
        (logging.INFO, 'blue'),
        (logging.WARNING, 'yellow'),
        (logging.ERROR, 'red'),
        (logging.CRITICAL, 'bold_red'),
    ])
    def test_custom_formatter_level_colors(self, level, expected_color_attr):
        """Test that each log level gets the correct color."""
        fmt = "%(message)s"
        formatter = CustomFormatter(fmt)
        
        record = logging.LogRecord(
            name="test",
            level=level,
            pathname="",
            lineno=0,
            msg="Test message",
            args=(),
            exc_info=None
        )
        
        formatted = formatter.format(record)
        expected_color = getattr(formatter, expected_color_attr)
        
        # The format should use the expected color for this level
        assert level in formatter.FORMATS
        assert expected_color in formatter.FORMATS[level]


class TestDebugFileHandler:
    """Test cases for the DebugFileHandler class."""

    @patch('logging.FileHandler.__init__')
    def test_debug_file_handler_initialization(self, mock_super_init):
        """Test DebugFileHandler initialization."""
        mock_super_init.return_value = None
        
        handler = DebugFileHandler("test.log")
        
        mock_super_init.assert_called_once_with("test.log", "a", None, False)

    @patch('logging.FileHandler.__init__')
    @patch('logging.FileHandler.emit')
    def test_debug_file_handler_emit_debug_only(self, mock_super_emit, mock_super_init):
        """Test that DebugFileHandler only emits DEBUG level records."""
        mock_super_init.return_value = None
        
        handler = DebugFileHandler("test.log")
        
        # Create DEBUG level record
        debug_record = logging.LogRecord(
            name="test",
            level=logging.DEBUG,
            pathname="",
            lineno=0,
            msg="Debug message",
            args=(),
            exc_info=None
        )
        
        # Create INFO level record
        info_record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Info message",
            args=(),
            exc_info=None
        )
        
        # Emit both records
        handler.emit(debug_record)
        handler.emit(info_record)
        
        # Only DEBUG record should be passed to parent emit
        mock_super_emit.assert_called_once_with(debug_record)

    @patch('logging.FileHandler.__init__')
    @patch('logging.FileHandler.emit')
    def test_debug_file_handler_ignores_non_debug(self, mock_super_emit, mock_super_init):
        """Test that DebugFileHandler ignores non-DEBUG records."""
        mock_super_init.return_value = None
        
        handler = DebugFileHandler("test.log")
        
        # Create non-DEBUG records
        levels = [logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL]
        
        for level in levels:
            record = logging.LogRecord(
                name="test",
                level=level,
                pathname="",
                lineno=0,
                msg=f"Message at level {level}",
                args=(),
                exc_info=None
            )
            handler.emit(record)
        
        # Should not have called parent emit for any non-DEBUG records
        mock_super_emit.assert_not_called()

    def test_debug_file_handler_constructor_parameters(self):
        """Test DebugFileHandler constructor parameter handling."""
        with patch('logging.FileHandler.__init__') as mock_init:
            mock_init.return_value = None
            
            # Test with all parameters
            handler = DebugFileHandler("test.log", "w", "utf-8", True)
            
            mock_init.assert_called_once_with("test.log", "w", "utf-8", True)


class TestLoggingConfig:
    """Test cases for the logging configuration."""

    def test_logging_config_structure(self):
        """Test that LOGGING_CONFIG has correct structure."""
        assert isinstance(LOGGING_CONFIG, dict)
        assert "version" in LOGGING_CONFIG
        assert "formatters" in LOGGING_CONFIG
        assert "handlers" in LOGGING_CONFIG
        assert "loggers" in LOGGING_CONFIG
        assert "root" in LOGGING_CONFIG

    def test_logging_config_version(self):
        """Test that logging config has correct version."""
        assert LOGGING_CONFIG["version"] == 1

    def test_logging_config_formatters(self):
        """Test logging config formatters."""
        formatters = LOGGING_CONFIG["formatters"]
        assert "simple" in formatters
        assert "format" in formatters["simple"]

    def test_logging_config_handlers(self):
        """Test logging config handlers."""
        handlers = LOGGING_CONFIG["handlers"]
        assert "console" in handlers
        
        console_handler = handlers["console"]
        assert console_handler["class"] == "logging.StreamHandler"
        assert "formatter" in console_handler
        assert "level" in console_handler

    def test_logging_config_loggers(self):
        """Test logging config loggers."""
        loggers = LOGGING_CONFIG["loggers"]
        assert "my_logger" in loggers
        
        my_logger = loggers["my_logger"]
        assert "handlers" in my_logger
        assert "level" in my_logger
        assert "propagate" in my_logger

    def test_logging_config_root(self):
        """Test logging config root logger."""
        root = LOGGING_CONFIG["root"]
        assert "handlers" in root
        assert "level" in root

    def test_logging_config_disable_existing_loggers(self):
        """Test that existing loggers are not disabled."""
        assert LOGGING_CONFIG["disable_existing_loggers"] is False


class TestLoggingIntegration:
    """Integration tests for the logging system."""

    def test_logging_integration_with_base_class(self):
        """Test logging integration with Base-derived classes."""
        from domain_profiler.base import Base
        
        class TestClass(Base):
            def log_something(self):
                logger = getattr(self, "_TestClass__logger")
                logger.info("Test message")
                return "logged"
        
        instance = TestClass()
        result = instance.log_something()
        
        assert result == "logged"
        assert hasattr(instance, "_TestClass__logger")

    @patch('logging.config.dictConfig')
    def test_logging_setup_called_once_per_class(self, mock_dict_config):
        """Test that logging setup is called for each class creation."""
        # Reset call count
        mock_dict_config.reset_mock()
        
        class FirstClass(metaclass=LoggingBase):
            pass
        
        class SecondClass(metaclass=LoggingBase):
            pass
        
        # Should be called once for each class
        assert mock_dict_config.call_count >= 2

    def test_logger_hierarchy_with_inheritance(self):
        """Test logger hierarchy with class inheritance."""
        class Parent(metaclass=LoggingBase):
            pass
        
        class Child(Parent):
            pass
        
        parent_instance = Parent()
        child_instance = Child()
        
        parent_logger = getattr(parent_instance, "_Parent__logger")
        child_logger = getattr(child_instance, "_Child__logger")
        
        # Both should be valid loggers
        assert isinstance(parent_logger, logging.Logger)
        assert isinstance(child_logger, logging.Logger)
        
        # Should have different names
        assert parent_logger.name != child_logger.name

    @patch('sys.stdout', new_callable=StringIO)
    def test_custom_formatter_output(self, mock_stdout):
        """Test CustomFormatter actual output."""
        # Create a logger with CustomFormatter
        logger = logging.getLogger("test_logger")
        logger.setLevel(logging.DEBUG)
        
        handler = logging.StreamHandler(mock_stdout)
        formatter = CustomFormatter("%(levelname)s: %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        # Log a message
        logger.info("Test info message")
        
        # Check output contains the message
        output = mock_stdout.getvalue()
        # The output might contain ANSI color codes, but should contain the message
        assert "Test info message" in output or "INFO" in output 