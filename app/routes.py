from werkzeug.exceptions import NotFound
from flask import request, redirect, url_for, flash
from app import app
from flask import (
    render_template,
    jsonify,
    session,
    redirect,
    url_for,
    request,
    flash,
    send_file,
)
from app.models import (
    save_analysis_with_details,
    is_file_already_uploaded,
)  # Import the functions from models

import os
import re
from datetime import datetime
import hashlib
import yara
import io
import requests
import json

from app import pdf_generator



from app.models import AnalysisReport, User, TTP, Signature, Screenshot, ExtractedData

BASE_URL = "http://localhost:8090"
# Replace with your actual API key
API_KEY = "a4ffc4d85a83177c90bfb59aa60ddce86bc035dd"


# Calculate the MD5 hash of a file
def calculate_md5(file_path):
    hasher = hashlib.md5()
    with open(file_path, "rb") as file:
        buf = file.read()
        hasher.update(buf)
    return hasher.hexdigest()


# Apply YARA rules to a file
def apply_yara_rules(file_path):
    matches = []
    yara_dir = app.config["YARA_DIR"]  # Use the YARA_DIR from the config
    for rule_file in os.listdir(yara_dir):
        rule_path = os.path.join(yara_dir, rule_file)
        if os.path.isfile(rule_path):
            rule = yara.compile(filepath=rule_path)
            rule_matches = rule.match(file_path)
            if rule_matches:
                matches.extend([match.rule for match in rule_matches])
    return matches


@app.route("/")
def home():
    return render_template(
        "admin/home.html", user_name=session.get("first_name", "Guest")
    )



def calculate_score(yara_rules_string, cuckoo_score):
    yara_rules_score = 0

    # Splitting the yara_rules_string to calculate its score
    yara_rules = yara_rules_string.split(", ")

    # Determining the yara_rules_score based on the number of rules
    if len(yara_rules) < 4:
        yara_rules_score = 1
    elif 4 <= len(yara_rules) < 8:
        yara_rules_score = 2
    else:
        yara_rules_score = 3

    print("yara rules score ", yara_rules_score)
    print("cuckoo score ", cuckoo_score)

    # Normalize scores to a scale of 0 to 10
    final_score = ((yara_rules_score / 3) * 3) + ((cuckoo_score / 10) * 7)

    return final_score
    



def addCuckooDataToDatabase(analysis_id, task_id):
    headers = {"Authorization": f"token {API_KEY}"}

    try:
        analysis_response = requests.get(
            BASE_URL + f'/analysis/{analysis_id}',
            headers=headers,
        )
        analysis_response.raise_for_status()  # Raise HTTPError for bad responses
    except requests.exceptions.RequestException as e:
        print(f"HTTP Request failed: {e}")
        return False
    
    try:
        analysis_response_json_file = analysis_response.json()
    except ValueError:
        print("Response is not valid JSON. Raw content:", analysis_response.text)
        return False
    
    try:
        analysis_response = requests.get(
            BASE_URL + f'/analysis/{analysis_id}/task/{task_id}/post',
            headers=headers,
        )
        analysis_response.raise_for_status()  # Raise HTTPError for bad responses
    except requests.exceptions.RequestException as e:
        print(f"HTTP Request failed: {e}")
        return False

    try:
        analysis_response_json = analysis_response.json()
    except ValueError:
        print("Response is not valid JSON. Raw content:", analysis_response.text)
        return False

    report = AnalysisReport.get_or_none(AnalysisReport.analysis_id == analysis_id)
    if not report:
        print("Report not found for analysis_id:", analysis_id)
        return False

    # Update report fields
    report.status = 'finished'

    # report.score = analysis_response_json.get("score", 0)

    report.score = calculate_score(report.report_content, analysis_response_json.get("score", 0))

    report.result = "Malicious" if report.score >= 8 else "Benign"  # Example categorization

    report.file_type = analysis_response_json_file['submitted']['type']
    report.media_type =analysis_response_json_file['submitted']['media_type'] 
    report.md5 = analysis_response_json_file['submitted']['md5']
    report.sha1 = analysis_response_json_file['submitted']['sha1']
    report.sha256 = analysis_response_json_file['submitted']['sha256']
    report.sha512 = analysis_response_json_file['submitted']['sha512']


    report.save()

    # Add Signatures
    for signature_data in analysis_response_json.get("signatures", []):
        Signature.create(
            report=report,
            name=signature_data.get("name", ""),
            short_description=signature_data.get("short_description", ""),
            description=signature_data.get("description", ""),
            score=signature_data.get("score", 0),
        )

    # Add TTPs
    for ttp_data in analysis_response_json.get("ttps", []):
        TTP.create(
            report=report,
            name=ttp_data.get("name", ""),
            tactics=",".join(ttp_data.get("tactics", [])),
            reference=ttp_data.get("reference", ""),
        )

    # Add Screenshots
    for screenshot_data in analysis_response_json.get("screenshot", []):
        Screenshot.create(
            report=report,
            name=screenshot_data.get("name", ""),
            percentage=screenshot_data.get("percentage", 0.0),
        )
    return True



@app.route("/files")
def files():
    # Retrieve the search query from the URL parameters
    # Default to an empty string if 'search' is not provided
    search_query = request.args.get('search', '').strip()

    # Base query: Retrieve all reports with necessary joins and ordering
    reports_query = AnalysisReport.select().join(
        User).order_by(AnalysisReport.timestamp.desc())

    # Apply search filtering if a search query is provided
    if search_query:
        reports_query = reports_query.where(
            # Search in 'file_name'
            (AnalysisReport.file_name.contains(search_query))
        )

    # Execute the query
    reports = reports_query.execute()

    for report in reports:
        if report.status == 'Processing':
            headers = {"Authorization": f"token {API_KEY}"}
            response = requests.get(
                BASE_URL+f'/analysis/{report.analysis_id}',
                headers=headers,
            )
            response = response.json()
            print(response)
            

            if response['state'] == "finished":
                report.task_id=response["tasks"][0]['id']
                report.save()
                
                try:
                    print(report.analysis_id, response['tasks'][0]['id'])
                    addCuckooDataToDatabase(
                        report.analysis_id, response['tasks'][0]['id'])
                except Exception as e:
                    print(f'error: {e} \n\n {response["target"]["filename"]}')
                    report.status = 'finished'
                    report.save()

    # Pass the reports and search query to the template
    return render_template("admin/files.html", reports=reports, search_query=search_query)


@app.route("/flag")
def flag():
    flaged_reports = AnalysisReport.select().where(
        AnalysisReport.flaged == True).execute()
    return render_template("admin/flag.html", flaged_reports=flaged_reports)


@app.route("/flag", methods=["POST"])
def flagFile():
    report_id = request.form.get("id")
    report = AnalysisReport.get(AnalysisReport.report_id == report_id)
    if (report.flaged):
        report.flaged = False
    else:
        report.flaged = True

    report.save()
    return redirect(url_for('flag'))


@app.route("/delete", methods=["POST"])
def delete():
    report_id = request.form.get("id")

    # Retrieve the report, handle case where it doesn't exist
    report = AnalysisReport.get_or_none(AnalysisReport.report_id == report_id)
    if not report:
        print("Report not found.", "danger")
        return redirect(url_for('files'))

    try:
        # Ensure the file path is safe and valid
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], report.file_name)
        if os.path.exists(file_path):
            os.remove(file_path)
        else:
            print("File not found on the server.", "warning")

        # Delete related TTP and Signature entries
        TTP.delete().where(TTP.report == report_id).execute()
        Signature.delete().where(Signature.report == report_id).execute()
        Screenshot.delete().where(Signature.report == report_id).execute()

        # Delete the report itself from the database
        report.delete_instance()
        print("Report and related data deleted successfully.", "success")

    except Exception as e:
        print(f"An error occurred: {str(e)}", "danger")

    return redirect(url_for('files'))



@app.route("/test")
def test():
    return render_template("admin/test.html")


@app.route("/help")
def help():
    return render_template("admin/help.html")


@app.route("/info")
def info():
    return render_template("admin/info.html")


@app.route("/upload", methods=["POST"])
def upload_file():
    if "user_id" not in session:
        return jsonify({"success": False, "redirect": url_for("auth.login")})

    if "file" not in request.files:
        return jsonify({"success": False, "message": "No file uploaded."}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"success": False, "message": "Empty file name."}), 400

    # Ensure the upload folder exists
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    # Save the file
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
    file.save(file_path)

    # Calculate the MD5 hash
    md5_hash = calculate_md5(file_path)

    # Check if the file has already been uploaded
    if is_file_already_uploaded(md5_hash):
        os.remove(file_path)  # Remove the duplicate file
        return jsonify(
            success=True, message="This file has already been uploaded.", md5=md5_hash
        )

    # File details
    file_name = file.filename
    file_size = os.path.getsize(file_path)  # Get file size in bytes
    upload_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Default to guest email
    user_email = session.get("email", "guest@example.com")

    # Apply YARA rules
    matched_rules = apply_yara_rules(file_path)
    ransomware_features = ", ".join(matched_rules) if matched_rules else "N/A"
    matched_count = len(matched_rules)


    # Apply YARA rules for strings in file
    rules = yara.compile(filepath='app/DetectRansomwareWords.yar')
    extracted_data_matches = rules.match(filepath=file_path)
    matched_strings = []


    for match in extracted_data_matches:
        for res1 in match.strings:
            for res2 in res1.instances:
                print(type(res2), res2.plaintext())
                matched_strings.append(res2.plaintext().decode('utf-8', errors='ignore'))


    with open(file_path, "rb") as file:
        content = file.read().decode("utf-8", errors="ignore")

    # Regular expressions for email, phone, and URLs
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    phone_pattern = r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b'
    url_pattern = r'https?://[^\s/$.?#].[^\s]*'

    emails = re.findall(email_pattern, content)
    phones = re.findall(phone_pattern, content)
    urls = re.findall(url_pattern, content)

    
    
    files = {'file': open(file_path, 'rb')}

    settings = {"platforms": [
        {"platform": "windows", "os_version": "10"}], "timeout": 120}
    data = {"settings": json.dumps(settings)}
    headers = {"Authorization": f"token {API_KEY}"}

    try:
        response = requests.post(
            f"{BASE_URL}/submit/file", headers=headers, files=files, data=data
        )
        print(response.json())
        response.raise_for_status()  # Raise an exception for HTTP errors
        response_data = response.json()
        json_data = {
            'timeout': 120,
            'priority': 3,
            'command': '',
            'orig_filename': False,
            'route': {},
            'platforms': [],
            'options': {},
            'fileid': '1',
        }

        response = requests.put(
            BASE_URL +
            f'/api/analyses/{response_data.get("analysis_id")}/settings',
            headers=headers,
            json=json_data,
        )
        
    except requests.RequestException as e:
        return jsonify({"success": False, "error": str(e)}), 500

    # Save the analysis to the database
    try:
        # Replace with your ORM logic (e.g., SQLAlchemy, Peewee)
        user = User.get(User.email == user_email)  # Get user by email
        report = AnalysisReport.create(
            user=user,
            report_content=ransomware_features,
            file_name=file_name,
            file_size=file_size,
            upload_time=upload_time,
            analysis_id=response_data.get("analysis_id"),
            flaged=False,
            strings= ", ".join(matched_strings) if matched_strings else None 
        )
        ExtractedData.create(
            report=report,
            emails=", ".join(emails) if emails else None,          # Join emails with commas
            phone_numbers=", ".join(phones) if phones else None,   # Join phone numbers with commas
            urls=", ".join(urls) if urls else None                 # Join URLs with commas
        )
    except Exception as e:
        return jsonify({"success": False, "error": f"Database error: {str(e)}"}), 500

    # Return success response with file path and report_id
    return jsonify(
        {
            "success": True,
            "redirect": url_for(
                "files"
            ),
        }
    )


@app.route("/report/<int:report_id>/fileInformation")
def report_details_file_information(report_id):
    # Fetch the report by ID from the database
    try:
        report = AnalysisReport.get(AnalysisReport.report_id == report_id)
    except AnalysisReport.DoesNotExist:
        flash("Report not found.")
        # Redirect to file list page if not found
        return redirect(url_for("files"))

    return render_template("admin/report-1.html", report=report)


@app.route("/report/<int:report_id>/generalExtractedInfromation")
def report_details_general_extracted_infromation(report_id):
    # Fetch the report by ID from the database
    try:
        report = AnalysisReport.get(AnalysisReport.report_id == report_id)
        extractedData = ExtractedData.select().where(ExtractedData.report == report_id)[0]

    except AnalysisReport.DoesNotExist:
        flash("Report not found.")
        # Redirect to file list page if not found
        return redirect(url_for("files"))

    return render_template("admin/report-2.html", report=report, extractedData=extractedData)


@app.route("/report/<int:report_id>/ransomewareExtractedFeatures")
def report_details_ransomeware_extracted_features(report_id):
    # Fetch the report by ID from the database
    try:
        report = AnalysisReport.get(AnalysisReport.report_id == report_id)
        
    except AnalysisReport.DoesNotExist:
        flash("Report not found.")
        # Redirect to file list page if not found
        return redirect(url_for("files"))

    return render_template("admin/report-3.html", report=report, matched_rules=report.report_content)


@app.route("/report/<int:report_id>/dynamicAnalysis")
def report_details_dynamic_analysis(report_id):
    # Fetch the report by ID from the database
    try:
        report = AnalysisReport.get(AnalysisReport.report_id == report_id)
        ttps = TTP.select().where(TTP.report == report_id)
        signatures = Signature.select().where(Signature.report == report_id)
        screenshots = Screenshot.select().where(Screenshot.report == report_id)

    except AnalysisReport.DoesNotExist:
        flash("Report not found.")
        return redirect(url_for("files"))

    return render_template(
        "admin/report-4.html",
        report=report,
        ttps=ttps,
        signatures=signatures,
        screenshots=screenshots,
    )

def sanitize_text(text, encoding='latin-1'):
    return text.encode(encoding, errors='replace').decode(encoding)


def generate_analysis_report(analysis_report):
    """
    Generate a detailed string report for a file analysis.
    
    Args:
        analysis_report (AnalysisReport): The analysis report instance.
        
    Returns:
        str: Formatted string report for the file analysis.
    """
    # Basic information
    report = (
        f"===== File Analysis Report =====\n"
        f"Report ID: {analysis_report.report_id}\n"
        f"User: {analysis_report.user.first_name} {analysis_report.user.last_name}\n"
        f"File Name: {analysis_report.file_name}\n"
        f"File Size: {analysis_report.file_size} bytes\n"
        f"File Type: {analysis_report.file_type or 'N/A'}\n"
        f"Media Type: {analysis_report.media_type or 'N/A'}\n"
        f"MD5: {analysis_report.md5 or 'N/A'}\n"
        f"SHA1: {analysis_report.sha1 or 'N/A'}\n"
        f"SHA256: {analysis_report.sha256 or 'N/A'}\n"
        f"SHA512: {analysis_report.sha512 or 'N/A'}\n"
        f"Upload Time: {analysis_report.upload_time}\n"
        f"Status: {analysis_report.status}\n"
        f"Result: {analysis_report.result or 'N/A'}\n"
        f"Score: {analysis_report.score or 'N/A'}\n"
        f"Flaged: {'Yes' if analysis_report.flaged else 'No'}\n"
        f"Strings: {analysis_report.strings or 'N/A'}\n"
        f"Timestamp: {analysis_report.timestamp}\n"
        f"Analysis ID: {analysis_report.analysis_id}\n"
        f"Task ID: {analysis_report.task_id or 'N/A'}\n\n"
    )

    # Extracted Data
    if analysis_report.extracted_data:
        report += "===== Extracted Data =====\n"
        extracted_data = analysis_report.extracted_data
        report += (
            f"  - Emails: {extracted_data.emails or 'None'}\n"
            f"  - Phone Numbers: {extracted_data.phone_numbers or 'None'}\n"
            f"  - URLs: {extracted_data.urls or 'None'}\n\n"
        )

    # TTPs
    if analysis_report.ttps:
        report += "===== Tactics, Techniques, and Procedures (TTPs) =====\n"
        for ttp in analysis_report.ttps:
            report += f"  - Name: {ttp.name}\n"
            report += f"    Tactics: {ttp.tactics}\n"
            report += f"    Reference: {ttp.reference}\n\n"

    # Signatures
    if analysis_report.signatures:
        report += "===== Signatures =====\n"
        for signature in analysis_report.signatures:
            report += f"  - Name: {signature.name}\n"
            report += f"    Short Description: {signature.short_description or 'None'}\n"
            report += f"    Description: {signature.description or 'None'}\n"
            report += f"    Score: {signature.score}\n\n"


    return report


def generateAiReport(formatted_report):
    """
    Send the formatted report to an AI service for analysis and summary.
    
    Args:
        formatted_report (str): The detailed file analysis report as a string.
        
    Returns:
        str: AI-generated summary of the report.
    """

    # Prepare the prompt
    prompt = (
        "Analyze the following file analysis report and summarize it into a concise and readable report. "
        "Highlight the most critical findings, including file details, analysis results, detected signatures, "
        "tactics (TTPs), and extracted data. Provide a risk assessment and any relevant recommendations. "
        "i want the response the healines like this ===== headline ===== \n\n"
        "i want the response the subhealines like this == subhealines == \n\n"
        "Here is the report:\n\n"
        f"{formatted_report}"
    )
    
    # Send the request to the AI service
    try:
        response = requests.get('https://text.pollinations.ai/'+prompt)
        response.raise_for_status()  # Raise an exception for HTTP errors
        ai_response = response.text
        return ai_response
    
    except requests.exceptions.RequestException as e:
        return f"Error communicating with the AI service: {e}"


@app.route("/report/download/<int:report_id>")
def download_report(report_id):
    # Retrieve the report
    try:
        analysis_report = AnalysisReport.get(AnalysisReport.report_id == report_id)
        # Fetch related data
        ttps = list(TTP.select().where(TTP.report == analysis_report))
        signatures = list(Signature.select().where(Signature.report == analysis_report))
        screenshots = list(Screenshot.select().where(Screenshot.report == analysis_report))
        extracted_data = ExtractedData.get(ExtractedData.report == analysis_report)

        # Link related data to the report object
        analysis_report.ttps = ttps
        analysis_report.signatures = signatures
        analysis_report.screenshots = screenshots
        analysis_report.extracted_data = extracted_data

        # Generate the report
        formatted_report = generate_analysis_report(analysis_report)
        formatted_report_uft_8 = sanitize_text(formatted_report, encoding="utf-8")

        ai_summery_report = generateAiReport(formatted_report_uft_8)

        formatted_report = sanitize_text(formatted_report)

        pdf_output = pdf_generator.generate_styled_pdf_report(formatted_report , ai_summery_report)

        return send_file(
            pdf_output,
            as_attachment=True,
            download_name=f"report_{analysis_report.report_id}.pdf",
            mimetype="application/pdf",
        )
    
    except AnalysisReport.DoesNotExist:
        flash("Report not found.")
        return redirect(url_for("files"))


