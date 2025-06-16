#!/usr/bin/env python3
"""
Script to fix bare except clauses in monitoring, auth, and mcp modules.
Updates them to use specific exceptions with proper error handling.
"""

import re
import logging
from pathlib import Path
from typing import List, Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def fix_scanner_server():
    """Fix bare except clauses in scanner_server.py"""
    file_path = Path("/home/louranicas/projects/claude-optimized-deployment/src/mcp/security/scanner_server.py")
    
    if not file_path.exists():
        logger.error(f"File not found: {file_path}")
        return
    
    content = file_path.read_text()
    
    # Fix line 400
    content = content.replace(
        """                        except:
                            pass""",
        """                        except (json.JSONDecodeError, KeyError, TypeError) as e:
                            logger.debug(f"Failed to parse npm outdated output: {e}")"""
    )
    
    # Fix line 434
    content = content.replace(
        """            except:
                result["raw_output"] = stdout""",
        """            except (json.JSONDecodeError, ValueError) as e:
                logger.warning(f"Failed to parse safety check output: {e}")
                result["raw_output"] = stdout"""
    )
    
    # Fix line 452
    content = content.replace(
        """                except:
                    pass""",
        """                except (json.JSONDecodeError, KeyError, TypeError) as e:
                    logger.debug(f"Failed to parse license information: {e}")"""
    )
    
    # Fix line 663
    content = content.replace(
        """                except:
                    pass""",
        """                except re.error as e:
                    logger.warning(f"Invalid regex pattern in custom_patterns[{i}]: {e}")"""
    )
    
    # Fix line 665
    content = content.replace(
        """        except:
            credential_patterns = SECRET_PATTERNS""",
        """        except (json.JSONDecodeError, TypeError) as e:
            logger.debug(f"Failed to parse custom patterns, using defaults: {e}")
            credential_patterns = SECRET_PATTERNS"""
    )
    
    file_path.write_text(content)
    logger.info(f"Fixed bare except clauses in {file_path}")


def fix_supply_chain_server():
    """Fix bare except clauses in supply_chain_server.py"""
    file_path = Path("/home/louranicas/projects/claude-optimized-deployment/src/mcp/security/supply_chain_server.py")
    
    if not file_path.exists():
        logger.error(f"File not found: {file_path}")
        return
    
    content = file_path.read_text()
    
    # Fix line 704
    content = content.replace(
        """        except:
            pass""",
        """        except (asyncio.TimeoutError, subprocess.SubprocessError, OSError) as e:
            logger.debug(f"Failed to get Python package license for {package_name}: {e}")"""
    )
    
    file_path.write_text(content)
    logger.info(f"Fixed bare except clauses in {file_path}")


def main():
    """Main function to fix all bare except clauses."""
    logger.info("Starting to fix bare except clauses...")
    
    fix_scanner_server()
    fix_supply_chain_server()
    
    logger.info("Completed fixing bare except clauses!")
    
    # Now let's also update all modules to use the new error handling system
    logger.info("\nUpdating modules to use centralized error handling...")
    
    # Update imports in monitoring modules
    monitoring_files = [
        "/home/louranicas/projects/claude-optimized-deployment/src/monitoring/health.py",
        "/home/louranicas/projects/claude-optimized-deployment/src/monitoring/tracing.py",
        "/home/louranicas/projects/claude-optimized-deployment/src/monitoring/mcp_integration.py",
        "/home/louranicas/projects/claude-optimized-deployment/src/monitoring/alerts.py",
        "/home/louranicas/projects/claude-optimized-deployment/src/monitoring/metrics.py",
        "/home/louranicas/projects/claude-optimized-deployment/src/monitoring/sla.py"
    ]
    
    for file_path in monitoring_files:
        path = Path(file_path)
        if path.exists():
            logger.info(f"Updating {path.name} to use error handler...")
            update_file_with_error_handler(path)


def update_file_with_error_handler(file_path: Path):
    """Update a file to use the centralized error handler."""
    content = file_path.read_text()
    
    # Check if already using error handler
    if "from src.core.error_handler import" in content:
        logger.debug(f"{file_path.name} already uses error handler")
        return
    
    # Add import after other imports
    lines = content.split('\n')
    import_index = 0
    
    # Find the last import statement
    for i, line in enumerate(lines):
        if line.startswith('import ') or line.startswith('from '):
            import_index = i
    
    # Insert error handler import
    error_handler_import = "\nfrom src.core.error_handler import (\n    handle_errors, async_handle_errors, log_error,\n    ServiceUnavailableError, ExternalServiceError, ConfigurationError\n)"
    
    lines.insert(import_index + 1, error_handler_import)
    
    # Write back
    file_path.write_text('\n'.join(lines))
    logger.info(f"Updated {file_path.name} with error handler imports")


if __name__ == "__main__":
    main()