# app/models.py
from peewee import (
    Model,
    CharField,
    ForeignKeyField,
    TextField,
    DateTimeField,
    AutoField,
    IntegerField,
    BooleanField,
    FloatField,
)
from datetime import datetime
from . import db


class BaseModel(Model):
    class Meta:
        database = db


class User(BaseModel):
    user_id = AutoField()
    first_name = CharField()
    last_name = CharField()
    email = CharField(unique=True)
    password = CharField()

    def __str__(self):
        return f"{self.first_name} {self.last_name}"


class AnalysisReport(BaseModel):
    report_id = AutoField()
    user = ForeignKeyField(User, backref="reports", on_delete="CASCADE")
    report_content = TextField()
    file_name = CharField()  # Add the file name
    file_size = IntegerField()  # Add the file size
    
    file_type = CharField(null=True)  # Type (e.g., PE32 executable)
    media_type = CharField(null=True)  # Media type (e.g., application/x-dosexec)
    md5 = CharField(null=True)  # MD5 hash
    sha1 = CharField(null=True)  # SHA1 hash
    sha256 = CharField(null=True)  # SHA256 hash
    sha512 = CharField(null=True)  # SHA512 hash

    upload_time = DateTimeField(default=datetime.now)  # Add the upload time
    # Add the status (processing, done)
    status = CharField(default="Processing")
    # Add the status (Benign, Suspicious, Malicious, etc.)
    result = CharField(null=True)
    score = IntegerField(null=True)  # Add the score
    timestamp = DateTimeField(default=datetime.now)
    flaged = BooleanField(default=False)
    strings = CharField(null=True)
    analysis_id = CharField()
    task_id = CharField(null=True)

    def __str__(self):
        return (
            f"Report {self.report_id} for {self.user.first_name} {self.user.last_name}"
        )


class TTP(BaseModel):
    ttp_id = AutoField()
    report = ForeignKeyField(
        AnalysisReport, backref="ttps", on_delete="CASCADE")
    name = CharField()
    tactics = TextField()  # Store as comma-separated values
    reference = CharField()

    def __str__(self):
        return f"TTP: {self.name}, Tactics: {self.tactics}"


class Signature(BaseModel):
    signature_id = AutoField()
    report = ForeignKeyField(
        AnalysisReport, backref="signatures", on_delete="CASCADE")
    name = CharField()
    short_description = TextField(null=True)  # Optional field
    description = TextField(null=True)  # Optional field
    score = IntegerField(default=0)  # Default score

    def __str__(self):
        return f"Signature: {self.name}, Score: {self.score}"


class Screenshot(BaseModel):
    screenshot_id = AutoField()
    report = ForeignKeyField(
        AnalysisReport, backref="screenshots", on_delete="CASCADE")
    name = CharField()
    percentage = FloatField()

    def __str__(self):
        return f"Screenshot: {self.name}, Percentage: {self.percentage}"


class ExtractedData(BaseModel):
    report = ForeignKeyField(
        AnalysisReport, backref="signatures", on_delete="CASCADE"
    )
    emails = TextField(null=True)  
    phone_numbers = TextField(null=True)  
    urls = TextField(null=True) 

    
    def __str__(self):
        return f"ExtractedData: emails: {self.emails}, phone_numbers: {self.phone_numbers}, urls: {self.urls}"



# Function to save analysis to the database
def save_analysis_with_details(
    file_name,
    file_path,
    file_size,
    upload_time,
    user,
    md5,
    ransomware_features,
    status,
    result,
    score,
    flaged,
    analysis_id,
    task_id,
    ttps_list,
    signatures_list,
    screenshots_list,
):
    # Create the analysis report
    report = AnalysisReport.create(
        user=user,
        report_content=f"File: {file_name}\nPath: {file_path}\nSize: {file_size}\nFeatures: {ransomware_features}\nStatus: {status}\nScore: {score}\n Flaged: {flaged}",
        file_name=file_name,
        file_size=file_size,
        upload_time=upload_time,
        status=status,
        score=score,
        flaged=flaged,
    )

    # Save TTPS data
    for ttp in ttps_list:
        TTP.create(
            report=report,
            name=ttp["name"],
            tactics=", ".join(ttp["tactics"]),
            reference=ttp["reference"],
        )

    # Save Signatures data
    for signature in signatures_list:
        Signature.create(
            report=report,
            name=signature["name"],
            short_description=signature.get("short_description", ""),
            description=signature.get("description", ""),
            score=signature.get("score", 0),
            # Convert tags list to string
            tags=", ".join(signature.get("tags", [])),
            family=signature.get("family", ""),
        )

    # Save Screenshots data
    for screenshot in screenshots_list:
        Screenshot.create(
            report=report,
            name=screenshot["name"],
            percentage=screenshot["percentage"],
        )


# Function to check if file has already been uploaded (based on md5 hash)
def is_file_already_uploaded(md5_hash):
    return (
        AnalysisReport.select()
        .where(AnalysisReport.report_content.contains(md5_hash))
        .exists()
    )


# Function to check if file has already been analyzed (based on md5 hash)
def is_file_analyzed(md5_hash):
    return (
        AnalysisReport.select()
        .where(AnalysisReport.report_content.contains(md5_hash))
        .exists()
    )
