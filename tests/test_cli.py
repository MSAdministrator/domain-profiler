"""Tests for the CLI functionality."""

import pytest
from unittest.mock import Mock, patch
import fire

from domain_profiler.__main__ import main
from domain_profiler.profiler import Profiler


class TestCLI:
    """Test cases for the CLI interface."""

    @patch('domain_profiler.__main__.fire.Fire')
    @patch('domain_profiler.__main__.Profiler')
    def test_main_function_calls_fire(self, mock_profiler, mock_fire):
        """Test that main function properly calls Fire with Profiler."""
        main()

        mock_fire.assert_called_once_with(mock_profiler)

    @patch('domain_profiler.__main__.fire.Fire')
    def test_main_function_integration(self, mock_fire):
        """Test main function integration."""
        main()

        # Fire should be called with Profiler class
        args, kwargs = mock_fire.call_args
        assert args[0] == Profiler

    def test_main_function_exists(self):
        """Test that main function is properly defined."""
        from domain_profiler.__main__ import main
        assert callable(main)

    @patch('sys.argv', ['domain-profiler', 'run', 'example.com'])
    @patch('domain_profiler.__main__.fire.Fire')
    def test_cli_entry_point(self, mock_fire):
        """Test CLI entry point behavior."""
        # This would normally be called by the CLI
        from domain_profiler.__main__ import main
        main()

        mock_fire.assert_called_once_with(Profiler)

    def test_cli_module_name_check(self):
        """Test that CLI module can be run as __main__."""
        # This tests the if __name__ == "__main__": block
        import domain_profiler.__main__ as cli_module
        
        # The module should have the main function
        assert hasattr(cli_module, 'main')
        assert callable(cli_module.main)

    @patch('domain_profiler.profiler.DNSCheck')
    def test_cli_profiler_run_method(self, mock_dns_check, sample_domain):
        """Test that the Profiler.run method works as expected for CLI."""
        mock_dns_instance = Mock()
        mock_dns_check.return_value = mock_dns_instance
        mock_dns_instance.get_report.return_value = {
            'domain': sample_domain,
            'dns': {'A': ['93.184.216.34']}
        }

        profiler = Profiler()
        result = profiler.run(sample_domain)

        assert result['domain'] == sample_domain
        assert 'dns' in result

    @patch('domain_profiler.profiler.Url')
    @patch('domain_profiler.profiler.DNSCheck')
    def test_cli_profiler_run_with_live_flag(self, mock_dns_check, mock_url, sample_domain):
        """Test CLI profiler run method with live flag."""
        # Setup DNS mock
        mock_dns_instance = Mock()
        mock_dns_check.return_value = mock_dns_instance
        mock_dns_instance.get_report.return_value = {'domain': sample_domain}

        # Setup URL mock
        mock_url_instance = Mock()
        mock_url.return_value = mock_url_instance
        mock_url_instance.to_json.return_value = {'url': sample_domain, 'is_alive': True}

        profiler = Profiler()
        result = profiler.run(sample_domain, live=True)

        assert result['domain'] == sample_domain
        assert result['url'] == sample_domain
        assert result['is_alive'] is True

    def test_fire_integration_signature(self):
        """Test that Profiler class has proper method signature for Fire."""
        profiler = Profiler()
        
        # Fire should be able to inspect the run method
        assert hasattr(profiler, 'run')
        assert callable(profiler.run)
        
        # Check method signature
        import inspect
        sig = inspect.signature(profiler.run)
        
        # Should have domain parameter
        assert 'domain' in sig.parameters
        # Should have live parameter with default
        assert 'live' in sig.parameters
        assert sig.parameters['live'].default is False

    @pytest.mark.integration
    def test_cli_fire_configuration(self):
        """Test that Fire is properly configured for the CLI."""
        # This test ensures Fire can properly parse the Profiler class
        profiler = Profiler()
        
        # These are the expected CLI commands that Fire should be able to generate
        expected_methods = ['run']
        
        for method_name in expected_methods:
            assert hasattr(profiler, method_name)
            assert callable(getattr(profiler, method_name))

    def test_docstring_availability_for_help(self):
        """Test that docstrings are available for Fire's help generation."""
        from domain_profiler.__main__ import main
        from domain_profiler.profiler import Profiler
        
        # Main function should have docstring
        assert main.__doc__ is not None
        assert "entry point" in main.__doc__.lower()
        
        # Profiler should have methods with docstrings
        profiler = Profiler()
        if hasattr(profiler.run, '__doc__') and profiler.run.__doc__:
            # If docstring exists, it should be meaningful
            assert len(profiler.run.__doc__.strip()) > 0

    @patch('builtins.print')
    @patch('domain_profiler.profiler.DNSCheck')
    def test_cli_output_format(self, mock_dns_check, mock_print, sample_domain):
        """Test that CLI output can be properly formatted."""
        mock_dns_instance = Mock()
        mock_dns_check.return_value = mock_dns_instance
        mock_dns_instance.get_report.return_value = {
            'domain': sample_domain,
            'dns': {'A': ['93.184.216.34']},
            'ips': {'93.184.216.34': {'host': 'example.com'}}
        }

        profiler = Profiler()
        result = profiler.run(sample_domain)

        # Result should be serializable (for Fire's output)
        import json
        try:
            json.dumps(result)
            serializable = True
        except (TypeError, ValueError):
            serializable = False

        assert serializable, "CLI output should be JSON serializable"

    def test_cli_module_imports(self):
        """Test that CLI module imports are correct."""
        import domain_profiler.__main__ as cli_module
        
        # Should import fire
        assert hasattr(cli_module, 'fire')
        
        # Should import Profiler
        assert hasattr(cli_module, 'Profiler')
        
        # Should be the correct Profiler class
        assert cli_module.Profiler == Profiler

    @pytest.mark.parametrize("args", [
        ['run', 'example.com'],
        ['run', 'example.com', '--live'],
        ['run', 'https://example.com'],
        ['run', '192.168.1.1'],
    ])
    def test_cli_argument_variations(self, args):
        """Test various CLI argument combinations."""
        # This tests that Fire can handle different argument patterns
        profiler = Profiler()
        
        # Fire should be able to parse these argument patterns
        # We're testing the method signature compatibility
        if len(args) >= 2:  # Has domain
            domain = args[1]
            live = '--live' in args or 'live' in args
            
            # Method should be callable with these parameters
            import inspect
            sig = inspect.signature(profiler.run)
            
            # Should be able to bind the arguments
            try:
                bound = sig.bind(domain, live=live)
                can_bind = True
            except TypeError:
                can_bind = False
                
            assert can_bind, f"Should be able to bind arguments: {args}" 