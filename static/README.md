# CipherScope Website

This directory contains the static website files for CipherScope.

## Files

- `index.html` - Main website page
- `style.css` - Additional CSS styles
- `README.md` - This file

## Design

The website is inspired by [rustup.rs](https://rustup.rs) with a clean, minimal design featuring:

- **Gradient background** with modern card-based layout
- **Copy-to-clipboard functionality** for code snippets
- **Responsive design** that works on mobile and desktop
- **Language tags** showing all 10 supported programming languages
- **Feature highlights** with icons and descriptions
- **Quick start section** with installation and usage examples

## Usage

Simply serve the `index.html` file with any static web server:

```bash
# Using Python
python -m http.server 8000

# Using Node.js
npx serve .

# Using any web server
# Point to the static/ directory
```

## Customization

To customize the website:

1. Edit `index.html` for content changes
2. Modify `style.css` for styling updates
3. Update GitHub links and repository URLs as needed
4. Add your own favicon and meta tags

The design is intentionally minimal and focused on the core functionality, similar to rustup.rs.
