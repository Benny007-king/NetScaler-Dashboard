# שימוש בגרסת פייתון רזה ועדכנית
FROM python:3.9-slim

# הגדרת תיקיית העבודה בתוך הקונטיינר
WORKDIR /app

# העתקת קובץ הדרישות והתקנת הספריות
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# העתקת שאר קבצי הפרויקט
COPY . .

# חשיפת הפורט שעליו האפליקציה רצה (מוגדר ב-.env כ-5000)
EXPOSE 5000

# הרצת האפליקציה
CMD ["python", "app.py"]
