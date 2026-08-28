# Configuration file for the Sphinx documentation builder.
#
# This documentation set is the future public repo for the product docs,
# published like the other Cryptnox doc repos: GitHub Pages under
# https://docs.cryptnox.com/<repo_slug>/ and linked from the docs hub.

# -- Product identity: the ONLY lines to touch when the public name is decided --
product_name = "Cryptnox ID CLI"
repo_url = "https://github.com/cryptnox/cryptnox-id-cli"
repo_slug = repo_url.rsplit("/", 1)[-1]  # docs publish at docs.cryptnox.com/<repo_slug>/
cli_name = "cryptnox-id"  # primary binary; cnx-id + cryptnox-id-card are aliases

# -- Hardware / shop links: single source of truth, edit here, used doc-wide via
#    the |reader-*| / |readers-link| substitutions (see rst_prolog below).
#    Names and shop links match the cryptnox-cli README. --
readers_url = "https://cryptnox.com/cardreaders/"
reader_contact_name = "Cryptnox Smartcard Reader"
reader_contact_url = "https://shop.cryptnox.com/product/cryptnox-smartcard-reader/"
reader_mini_name = "Compact USB Mini Smartcard Reader"
reader_mini_url = "https://shop.cryptnox.com/product/mini-smartcard-reader/"
reader_contactless_name = "Cryptnox NFC Contactless Reader"
reader_contactless_url = "https://shop.cryptnox.com/product/cryptnox-contactless-reader/"

project = product_name
author = "Cryptnox"
copyright = "2026, Cryptnox"  # noqa: A001 — footer format matches docs.cryptnox.com/cryptnox-cli
release = "1.0.0"  # keep in sync with the CLI release (see internal release checklist)
version = release

# -- Versioned docs, same scheme as docs.cryptnox.com/cryptnox-hardware-wallet:
#    each minor version is published under /<repo_slug>/vMAJ.MIN/ and the site
#    root redirects to the newest (assembled in .github/workflows/docs.yml).
#    The sidebar dropdown (_templates/layout.html) is rendered from this list —
#    append the new slug when publishing a new minor version, oldest first.
docs_version = "v" + ".".join(release.split(".")[:2])  # e.g. "v0.1"
docs_versions = ["v0.1"]
if docs_version not in docs_versions:  # the version being built is always listed
    docs_versions.append(docs_version)

extensions = [
    "sphinx_copybutton",
    "sphinx.ext.todo",  # draft markers on stub pages; never rendered (see below)
]
templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

html_theme = "sphinx_rtd_theme"
html_theme_options = {
    # Same sidebar header as docs.cryptnox.com/cryptnox-cli (dark navy behind
    # the title + logo; title/logo colors come from custom.css)
    "style_nav_header_background": "#101f2e",
}
html_logo = "_static/cryptnox-logo.svg"
html_favicon = "_static/favicon.png"  # same icon as the cryptnox-hardware-wallet docs
html_static_path = ["_static"]
html_css_files = ["custom.css"]
html_js_files = ["custom.js"]
html_title = product_name
html_baseurl = f"https://docs.cryptnox.com/{repo_slug}/{docs_version}/"
html_context = {"docs_version": docs_version, "docs_versions": docs_versions}
html_show_sphinx = False  # drop the "Built with Sphinx" footer line, matching docs.cryptnox.com/cryptnox-cli
html_show_sourcelink = False  # no "View page source" link
html_copy_source = False  # and no _sources/*.rst.txt on the published site

# PDF output name for a local `make latexpdf` run. CI builds HTML only - pdflatex
# cannot render several characters these docs legitimately use.
latex_documents = [("index", f"{repo_slug}.tex", product_name, author, "manual")]

todo_include_todos = False  # .. todo:: blocks must never reach the published site

rst_prolog = f"""
.. |product| replace:: {product_name}
.. |cli| replace:: ``{cli_name}``
.. |readers-link| replace:: `Cryptnox card readers <{readers_url}>`__
.. |reader-contact| replace:: `{reader_contact_name} <{reader_contact_url}>`__
.. |reader-mini| replace:: `{reader_mini_name} <{reader_mini_url}>`__
.. |reader-contactless| replace:: `{reader_contactless_name} <{reader_contactless_url}>`__
"""
