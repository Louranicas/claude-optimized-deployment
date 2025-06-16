# Configuration file for the Sphinx documentation builder.
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import os
import sys
from datetime import datetime

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
sys.path.insert(0, os.path.abspath('../../src'))

# -- Project information -----------------------------------------------------

project = 'Claude-Optimized Deployment Engine (CODE)'
copyright = f'{datetime.now().year}, CODE Development Team'
author = 'CODE Development Team'
version = '1.0.0'
release = '1.0.0'

# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.autosummary',
    'sphinx.ext.napoleon',
    'sphinx.ext.viewcode',
    'sphinx.ext.intersphinx',
    'sphinx.ext.todo',
    'sphinx_rtd_theme',
    'sphinxext.opengraph',
    'myst_parser',
    'sphinx_copybutton',
    'sphinx_design',
    'sphinx_tabs.tabs',
    'sphinxcontrib.openapi',
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# The suffix(es) of source filenames.
source_suffix = {
    '.rst': None,
    '.md': 'myst_parser',
}

# The master toctree document.
master_doc = 'index'

# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.
html_theme = 'sphinx_rtd_theme'

# Theme options
html_theme_options = {
    'analytics_id': '',
    'analytics_anonymize_ip': False,
    'logo_only': True,
    'display_version': True,
    'prev_next_buttons_location': 'bottom',
    'style_external_links': False,
    'vcs_pageview_mode': '',
    'style_nav_header_background': '#2980B9',
    'collapse_navigation': True,
    'sticky_navigation': True,
    'navigation_depth': 4,
    'includehidden': True,
    'titles_only': False,
}

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

# Custom CSS files
html_css_files = [
    'custom.css',
]

# Custom JS files
html_js_files = [
    'custom.js',
]

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'sphinx'

# HTML context for theme customization
html_context = {
    'display_github': True,
    'github_user': 'your-org',
    'github_repo': 'claude-optimized-deployment',
    'github_version': 'main',
    'conf_py_path': '/docs/api/',
}

# -- Extension configuration -------------------------------------------------

# Napoleon settings
napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = False
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = False
napoleon_use_admonition_for_notes = False
napoleon_use_admonition_for_references = False
napoleon_use_ivar = False
napoleon_use_param = True
napoleon_use_rtype = True
napoleon_preprocess_types = False
napoleon_type_aliases = None
napoleon_attr_annotations = True

# Autodoc settings
autodoc_default_options = {
    'members': True,
    'member-order': 'bysource',
    'special-members': '__init__',
    'undoc-members': True,
    'exclude-members': '__weakref__'
}

# Autosummary settings
autosummary_generate = True
autosummary_generate_overwrite = False

# Intersphinx mapping
intersphinx_mapping = {
    'python': ('https://docs.python.org/3', None),
    'aiohttp': ('https://docs.aiohttp.org/en/stable/', None),
    'pydantic': ('https://pydantic-docs.helpmanual.io/', None),
}

# Todo extension settings
todo_include_todos = True

# MyST parser settings
myst_enable_extensions = [
    "colon_fence",
    "deflist",
    "dollarmath",
    "fieldlist",
    "html_admonition",
    "html_image",
    "linkify",
    "replacements",
    "smartquotes",
    "strikethrough",
    "substitution",
    "tasklist",
]

# Copy button settings
copybutton_prompt_text = r">>> |\.\.\. |\$ |In \[\d*\]: | {2,5}\.\.\.: | {5,8}: "
copybutton_prompt_is_regexp = True

# OpenGraph settings
ogp_site_url = "https://code-engine.io/docs/"
ogp_description_length = 300
ogp_image = "https://code-engine.io/images/logo.png"
ogp_site_name = "CODE Documentation"
ogp_type = "website"

# Sphinx design settings
sd_fontawesome_latex = True

# OpenAPI settings
openapi_spec = './openapi.yaml'

# Custom roles
def setup(app):
    app.add_css_file('custom.css')
    app.add_js_file('custom.js')
    
    # Custom directives
    from sphinx.util.docutils import docutils_namespace
    with docutils_namespace():
        from sphinx.directives.code import CodeBlock
        app.add_directive('code-example', CodeBlock)

# Language for content autogenerated by Sphinx
language = 'en'

# -- Options for LaTeX output ------------------------------------------------

latex_engine = 'pdflatex'
latex_elements = {
    'papersize': 'letterpaper',
    'pointsize': '10pt',
    'preamble': r'''
        \usepackage{charter}
        \usepackage[defaultsans]{lato}
        \usepackage{inconsolata}
    ''',
}

# Grouping the document tree into LaTeX files
latex_documents = [
    (master_doc, 'CODE.tex', 'CODE Documentation', 'CODE Development Team', 'manual'),
]

# -- Options for manual page output ------------------------------------------

# One entry per manual page
man_pages = [
    (master_doc, 'code', 'CODE Documentation', [author], 1)
]

# -- Options for Texinfo output ----------------------------------------------

# Grouping the document tree into Texinfo files
texinfo_documents = [
    (master_doc, 'CODE', 'CODE Documentation', author, 'CODE',
     'Claude-Optimized Deployment Engine for AI-powered infrastructure automation.', 'Miscellaneous'),
]

# -- Options for Epub output -------------------------------------------------

# Bibliographic Dublin Core info.
epub_title = project
epub_author = author
epub_publisher = author
epub_copyright = copyright

# A list of files that should not be packed into the epub file.
epub_exclude_files = ['search.html']

# -- Custom configuration ----------------------------------------------------

# Version info for the project
version_info = {
    'version': version,
    'release': release,
    'git_branch': os.environ.get('GIT_BRANCH', 'main'),
    'build_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
}

# Add version info to HTML context
html_context.update(version_info)

# Suppress warnings
suppress_warnings = ['image.nonlocal_uri']

# Show todos in output
todo_include_todos = True

# Include module names in output
add_module_names = False

# Sort members by type
autodoc_member_order = 'groupwise'

# Mock imports for modules that might not be available during build
autodoc_mock_imports = [
    'aiohttp',
    'pydantic',
    'kubernetes',
    'docker',
    'prometheus_client',
]

# Custom footer
html_show_sphinx = True
html_show_copyright = True

# Search language
html_search_language = 'en'

# Enable experimental features
experimental_html5_writer = True