from fpdf import FPDF
import re
import io

def add_title(pdf, title):
    """Adds a styled title to the PDF."""
    pdf.set_font("Arial", style="B", size=16)
    pdf.set_text_color(0, 51, 102)  # Dark Blue
    pdf.cell(0, 10, title, ln=True, align='C')
    pdf.ln(5)

def add_headline(pdf, text):
    """Adds a modern styled headline."""
    pdf.set_font("Arial", style="B", size=14)
    pdf.set_text_color(255, 255, 255)  # White text
    pdf.set_fill_color(0, 102, 204)  # Blue background
    pdf.cell(0, 8, text.strip('=').strip(), ln=True, align='L', fill=True)
    pdf.ln(2)

def add_subheadline(pdf, text):
    """Adds a styled subheadline."""
    pdf.set_font("Arial", style="I", size=12)
    pdf.set_text_color(0, 102, 204)  # Blue
    pdf.cell(0, 6, text.strip('=').strip(), ln=True, align='L')
    pdf.ln(2)

def add_key_value(pdf, key, value):
    """Adds a styled key-value pair."""
    pdf.set_font("Arial", style="B", size=12)
    pdf.set_text_color(0, 102, 102)  # Teal for the key
    pdf.cell(0, 6, f"{key}:", ln=False, align='L')
    
    pdf.set_font("Arial", size=12)
    pdf.set_text_color(0, 0, 0)  # Black for the value
    pdf.cell(0, 6, f" {value}", ln=True)
    pdf.ln(1)

def add_content(pdf, text):
    """Adds regular content with bold words styled."""
    pdf.set_font("Arial", size=12)
    pdf.set_text_color(0, 0, 0)  # Black

    # Handle **word** bold formatting
    parts = re.split(r"(\*\*.*?\*\*)", text)  # Split text by bold markers
    for part in parts:
        if part.startswith("**") and part.endswith("**"):  # Bold formatting
            pdf.set_font("Arial", style="B", size=12)
            pdf.write(6, part.strip('*'))
        else:
            pdf.set_font("Arial", size=12)
            pdf.write(6, part)
    pdf.ln()

def process_content_with_stars(pdf, content):
    """Processes content with headlines, subheadlines, key-value pairs, and regular text."""
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("=====") and line.endswith("====="):  # Main headlines
            add_headline(pdf, line)
        elif line.startswith("==") and line.endswith("=="):  # Subheadlines
            add_subheadline(pdf, line)
        elif line.startswith("**") and line.endswith(":"):  # Key-value pairs
            parts = line.strip('*').split(':', 1)
            if len(parts) == 2:
                key, value = map(str.strip, parts)
                add_key_value(pdf, key, value)
        else:  # Regular content
            add_content(pdf, line)

def generate_styled_pdf_report(report_content, ai_content):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Add the File Analysis Report section
    add_title(pdf, "File Analysis Report")
    process_content_with_stars(pdf, report_content)

    # Add the AI Analysis Report section
    add_title(pdf, "AI Analysis Report")
    process_content_with_stars(pdf, ai_content)

    # Generate PDF bytes
    pdf_bytes = pdf.output(dest='S').encode('latin-1', errors='replace')

    # Prepare the file for download
    output = io.BytesIO()
    output.write(pdf_bytes)
    output.seek(0)

    return output
