import sqlite3
from pathlib import Path

DB_PATH = "database.db"
conn = sqlite3.connect(DB_PATH)
c = conn.cursor()
c.execute("PRAGMA foreign_keys=OFF")
for table in ["notifications", "email_otps", "admin_audit_logs", "payments", "lesson_progress", "lessons", "cancellation_requests", "subscriptions", "courses", "plans", "users"]:
    c.execute(f"DROP TABLE IF EXISTS {table}")
c.execute("PRAGMA foreign_keys=ON")

c.execute("""CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    status TEXT DEFAULT 'active',
    university TEXT DEFAULT '',
    email_verified INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now'))
)""")

c.execute("""CREATE TABLE plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    price REAL NOT NULL,
    billing_cycle TEXT NOT NULL,
    stripe_price_id TEXT DEFAULT '',
    status TEXT DEFAULT 'active',
    trial_days INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
)""")

c.execute("""CREATE TABLE courses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    plan_id INTEGER NOT NULL,
    status TEXT DEFAULT 'draft',
    thumbnail_url TEXT DEFAULT '',
    level TEXT DEFAULT '',
    duration TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (plan_id) REFERENCES plans(id)
)""")

c.execute("""CREATE TABLE lessons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    course_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    content TEXT DEFAULT '',
    video_url TEXT DEFAULT '',
    position INTEGER DEFAULT 0,
    status TEXT DEFAULT 'published',
    duration_minutes INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
)""")

c.execute("""CREATE TABLE lesson_progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    lesson_id INTEGER NOT NULL,
    completed_at TEXT DEFAULT (datetime('now')),
    progress_percent INTEGER DEFAULT 0,
    UNIQUE(user_id, lesson_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (lesson_id) REFERENCES lessons(id) ON DELETE CASCADE
)""")

c.execute("""CREATE TABLE subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    plan_id INTEGER NOT NULL,
    start_date TEXT NOT NULL,
    end_date TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    stripe_customer_id TEXT DEFAULT '',
    stripe_subscription_id TEXT DEFAULT '',
    checkout_session_id TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (plan_id) REFERENCES plans(id)
)""")

c.execute("""CREATE TABLE payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    subscription_id INTEGER,
    plan_id INTEGER,
    stripe_invoice_id TEXT DEFAULT '',
    stripe_payment_intent_id TEXT DEFAULT '',
    stripe_checkout_session_id TEXT DEFAULT '',
    amount REAL NOT NULL,
    currency TEXT DEFAULT 'PHP',
    status TEXT NOT NULL,
    source TEXT DEFAULT '',
    paid_at TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (subscription_id) REFERENCES subscriptions(id),
    FOREIGN KEY (plan_id) REFERENCES plans(id)
)""")

c.execute("""CREATE TABLE cancellation_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subscription_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    reason TEXT DEFAULT '',
    cancel_mode TEXT DEFAULT 'period_end',
    status TEXT DEFAULT 'pending',
    created_at TEXT,
    processed_at TEXT,
    FOREIGN KEY (subscription_id) REFERENCES subscriptions(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
)""")

c.execute("""CREATE TABLE admin_audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id INTEGER,
    details TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (admin_id) REFERENCES users(id)
)""")

c.execute("""CREATE TABLE email_otps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    university TEXT DEFAULT '',
    otp_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    attempts INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
)""")

c.execute("""CREATE TABLE notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    link TEXT DEFAULT '',
    is_read INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)""")

plans = [
    ("Free Trial", "Try Substra Learn free for 7 days. Includes starter course access.", 0, "Free Trial", "", "active", 7),
    ("Starter", "Perfect for beginners. Access foundational courses to start your learning journey.", 299, "Monthly", "price_1TOcVdDtdr5Qfw8qvqee44fG", "active", 0),
    ("Professional", "For serious learners. Unlock intermediate and advanced courses with priority support.", 799, "Monthly", "price_1TOcW2Dtdr5Qfw8q6zTxiKoU", "active", 0),
    ("Enterprise", "Full access to every course. Best for teams and power learners who want it all.", 1499, "Monthly", "price_1TOcWJDtdr5Qfw8q7R2twpot", "active", 0),
]
c.executemany("""INSERT INTO plans (name, description, price, billing_cycle, stripe_price_id, status, trial_days) VALUES (?, ?, ?, ?, ?, ?, ?)""", plans)

courses = [
    ("Introduction to Web Development", "Learn how the web works, then build structured, styled, interactive pages using HTML, CSS, and JavaScript fundamentals.", 2, "published", "Beginner", "3 hours"),
    ("Python Programming Basics", "Master Python syntax, data types, functions, control flow, and problem-solving through practical examples.", 2, "published", "Beginner", "4 hours"),
    ("Database Design & SQL", "Design relational databases, model relationships, and write reliable SQL queries for real applications.", 3, "published", "Intermediate", "5 hours"),
    ("Full-Stack Web Application", "Build a complete web application with authentication, database models, forms, dashboards, and deployment preparation.", 3, "published", "Intermediate", "7 hours"),
    ("Cloud Computing & DevOps", "Deploy and manage applications in the cloud with environment variables, CI/CD, logging, and release workflows.", 4, "published", "Advanced", "6 hours"),
    ("Machine Learning Foundations", "Explore data preparation, model training, evaluation metrics, and responsible ML workflows.", 4, "published", "Advanced", "6 hours"),
]
c.executemany("""INSERT INTO courses (title, description, plan_id, status, level, duration) VALUES (?, ?, ?, ?, ?, ?)""", courses)

def lesson_content(title, goals, explanation, walkthrough, example, practice, checkpoint):
    return f"""{title}

Learning goals:
{goals}

Full explanation:
{explanation}

Step-by-step walkthrough:
{walkthrough}

Example:
{example}

Practice activity:
{practice}

Checkpoint before moving on:
{checkpoint}

Summary:
You should now be able to explain the main idea of this lesson, apply it in a small task, and connect it to the next lesson in the course."""

lessons = [
    (1, "Welcome to Web Development", lesson_content(
        "Welcome to Web Development",
        "- Explain what happens when a user opens a website\n- Identify the roles of HTML, CSS, and JavaScript\n- Understand how the course project will be built step by step",
        "A website is a collection of files and services that work together. When someone enters a web address, the browser sends a request to a server. The server responds with files such as HTML, CSS, JavaScript, images, and data. The browser then reads those files and turns them into the page the user sees. HTML creates the structure, CSS controls the presentation, and JavaScript adds behavior such as buttons, validation, animations, and dynamic updates.",
        "1. Open any website and notice the visible parts: text, buttons, images, menus, and forms.\n2. Imagine the HTML as the skeleton that labels each part.\n3. Imagine CSS as the clothing and layout that makes the skeleton look polished.\n4. Imagine JavaScript as the muscles that let the page respond to user actions.\n5. By the end of this course, you will combine all three layers into a small interactive page.",
        "A login page uses HTML for the email and password fields, CSS to make the form look clean, and JavaScript to show a message if the password is too short before the form is submitted.",
        "Sketch a simple web page on paper. Label which parts are structure, which parts are styling, and which parts should be interactive.",
        "Can you describe, in your own words, the difference between HTML, CSS, and JavaScript?"
    ), "", 1, "published", 18),
    (1, "HTML Fundamentals", lesson_content(
        "HTML Fundamentals",
        "- Build a valid HTML document\n- Use headings, paragraphs, lists, links, images, and forms\n- Choose semantic tags that describe meaning",
        "HTML stands for HyperText Markup Language. It is not a programming language; it is a markup language used to describe the meaning and structure of content. A heading tells the browser and assistive technologies that a piece of text is a section title. A paragraph tells the browser that text belongs together. A link connects one page to another. Semantic HTML is important because it improves accessibility, search engine understanding, and long-term maintainability.",
        "1. Start with a document structure: doctype, html, head, and body.\n2. Add a main heading with h1.\n3. Use h2 or h3 for subsections.\n4. Use p for paragraphs and ul or ol for lists.\n5. Use a for links and img for images.\n6. Use form, label, input, and button when collecting user input.\n7. Check that every form input has a label so the page is accessible.",
        "A student profile page might use header for the top area, main for the profile content, section for education and skills, and footer for contact information. This is better than using only generic div elements because the structure has meaning.",
        "Create a student profile page with your name, university, course interests, three skills, and a contact form with email and message fields.",
        "Can someone understand the purpose of each section by reading only your HTML tags?"
    ), "", 2, "published", 35),
    (1, "CSS Basics and Layout", lesson_content(
        "CSS Basics and Layout",
        "- Apply colors, spacing, borders, and typography\n- Understand selectors and reusable classes\n- Use Flexbox or Grid to build responsive layouts",
        "CSS controls how HTML appears on the screen. A selector chooses which elements to style, and declarations define what changes. Good CSS is reusable and consistent. Instead of styling every element separately, you create shared classes such as card, button, or page-title. Layout is one of the most important CSS skills. Flexbox is useful for one-dimensional layouts like navigation bars, while Grid is useful for two-dimensional layouts like dashboards and card galleries.",
        "1. Set a base font and background on the body.\n2. Create a reusable card class with padding, border radius, and shadow.\n3. Use margin and gap to create readable spacing.\n4. Use Flexbox for rows of items that need alignment.\n5. Add media queries so the layout adapts on mobile screens.\n6. Test the page by resizing the browser.",
        "A course card can have a thumbnail at the top, content in the middle, and a button at the bottom. Display flex with flex-direction: column lets the card keep a clean vertical structure, while gap keeps spacing consistent.",
        "Style the student profile page from the HTML lesson. Add a card layout, a button style, a clean color palette, and a mobile-friendly design.",
        "Does your layout still look readable when the screen width is small?"
    ), "", 3, "published", 40),
    (1, "JavaScript Interactivity", lesson_content(
        "JavaScript Interactivity",
        "- Select HTML elements with JavaScript\n- Listen for user events\n- Update the page without reloading it\n- Perform simple validation",
        "JavaScript makes a page interactive. It can read values from inputs, respond to clicks, calculate results, show or hide messages, and send data to a server. The usual pattern is: select an element, listen for an event, then run a function. JavaScript should improve the user experience, but important validation should also happen on the server because users can disable or bypass browser scripts.",
        "1. Select an element using document.querySelector.\n2. Attach an event listener such as click or input.\n3. Read the current value or state.\n4. Decide what should happen.\n5. Update text, classes, or attributes on the page.\n6. Keep the code small and readable by using functions.",
        "A registration form can check whether the password and confirm password fields match. If they do not match, JavaScript shows a red warning. When they match, the warning disappears. The server should still verify the same rule after submission.",
        "Add live validation to a form. Show a message when a field is empty, when an email does not look valid, or when two password fields do not match.",
        "Can your script explain exactly what the user needs to fix before submitting the form?"
    ), "", 4, "published", 42),
    (2, "Python Setup", lesson_content(
        "Python Setup",
        "- Install Python and confirm it works\n- Run a Python file from the terminal\n- Understand why virtual environments are useful",
        "Python is widely used for web development, automation, data analysis, and machine learning. Before writing programs, you need a reliable environment. A virtual environment is a private workspace for one project's packages. It prevents one project from accidentally breaking another project by using different package versions.",
        "1. Install Python from the official installer or your system package manager.\n2. Open a terminal and run python --version or py --version.\n3. Create a project folder.\n4. Create a virtual environment.\n5. Activate it.\n6. Install packages only inside that environment.\n7. Save package names in requirements.txt when sharing the project.",
        "For a Flask project, you might create a virtual environment, activate it, then run pip install flask python-dotenv. This keeps Flask installed for that project without changing every Python project on your computer.",
        "Create a file named hello.py that prints your name, university, and one programming goal. Run it from the terminal.",
        "Can you explain why a project should have its own virtual environment?"
    ), "", 1, "published", 25),
    (2, "Variables and Data Types", lesson_content(
        "Variables and Data Types",
        "- Store values in variables\n- Use strings, numbers, booleans, lists, and dictionaries\n- Choose the right data type for a task",
        "A variable is a name that points to a value. Data types describe what kind of value is being stored. Strings hold text, integers and floats hold numbers, booleans hold true or false values, lists hold ordered collections, and dictionaries hold named values. Choosing the right type makes your program easier to understand and less likely to break.",
        "1. Use clear variable names such as student_name instead of x.\n2. Store text in strings.\n3. Store whole numbers in integers and decimal numbers in floats.\n4. Use booleans for yes/no states.\n5. Use lists when you need multiple items in order.\n6. Use dictionaries when each value needs a label.\n7. Print values using f-strings for readable output.",
        "A student can be represented as a dictionary: name, university, year_level, and enrolled_courses. The enrolled courses can be a list because the student may have more than one course.",
        "Create a student dictionary with your name, university, and three skills. Print a short profile sentence using an f-string.",
        "Can you identify when to use a list instead of a dictionary?"
    ), "", 2, "published", 35),
    (2, "Control Flow and Loops", lesson_content(
        "Control Flow and Loops",
        "- Use if, elif, and else to make decisions\n- Repeat work with for and while loops\n- Combine conditions and loops to process many values",
        "Control flow lets a program choose different paths. If a password is too short, the program shows an error. If a student score is high enough, the program marks the student as passed. Loops let the program repeat work without copying code. A for loop is best when you already have a collection to process. A while loop is useful when repetition continues until a condition changes.",
        "1. Write the condition you want to test.\n2. Place the code for the true case under if.\n3. Add elif for extra cases.\n4. Add else for the default case.\n5. Use a for loop to process each item in a list.\n6. Keep loop logic simple and avoid infinite while loops.",
        "A grade checker can loop through a list of scores. For each score, it can print Excellent, Passed, or Needs improvement depending on the value.",
        "Write a program that loops through five quiz scores, prints feedback for each score, and calculates the average score.",
        "Can you trace your program line by line and predict the output before running it?"
    ), "", 3, "published", 38),
    (2, "Functions and Modules", lesson_content(
        "Functions and Modules",
        "- Write reusable functions\n- Pass information through parameters\n- Return results\n- Organize code with modules",
        "A function is a named block of code that performs a specific job. Functions reduce repetition and make programs easier to test. A good function does one clear thing. Parameters let the caller provide input, and return values send results back. Modules are files or libraries that contain reusable code. Python includes many standard modules, and projects can also define their own.",
        "1. Identify repeated logic in your program.\n2. Give the function a clear verb-based name.\n3. Decide what parameters it needs.\n4. Write the calculation or action inside the function.\n5. Return a result instead of printing when possible.\n6. Import modules when you need reusable tools such as datetime, random, or math.",
        "A tuition calculator might use calculate_total(units, price_per_unit) to return the total fee. The program can then print the result, save it, or display it in a web page.",
        "Create three functions: calculate_average, get_letter_grade, and format_student_report. Use them together to print a simple grade report.",
        "Can each function be understood without reading the entire program?"
    ), "", 4, "published", 40),
    (3, "Database Concepts", lesson_content(
        "Database Concepts",
        "- Explain tables, rows, columns, primary keys, and foreign keys\n- Design simple relationships\n- Understand why structure matters",
        "A database stores information in an organized way. In a relational database, data is grouped into tables. Each row represents one record, and each column represents one property. A primary key uniquely identifies a row. A foreign key connects one table to another. Good database design avoids unnecessary duplication and makes it easier to answer questions with queries.",
        "1. Identify the main objects in your application.\n2. Turn each object into a table.\n3. Choose columns for each table.\n4. Add a primary key to every table.\n5. Use foreign keys to represent relationships.\n6. Decide which fields are required and which can be optional.\n7. Test the design by asking common business questions.",
        "In a learning platform, users, plans, courses, lessons, subscriptions, and payments can each be separate tables. A course belongs to a plan, a lesson belongs to a course, and a subscription belongs to a user.",
        "Design a database schema for a library system with students, books, and borrow records. Identify primary and foreign keys.",
        "Can your schema answer who borrowed which book and when it should be returned?"
    ), "", 1, "published", 35),
    (3, "SELECT Queries", lesson_content(
        "SELECT Queries",
        "- Retrieve data from a table\n- Filter rows with WHERE\n- Sort and limit results\n- Read query output carefully",
        "SELECT is used to read data from a database. You can select all columns or only the columns you need. WHERE filters rows, ORDER BY sorts results, and LIMIT controls how many rows are returned. Clear queries are important because reports, dashboards, and admin pages depend on accurate data.",
        "1. Start with SELECT and the columns you need.\n2. Add FROM and the table name.\n3. Add WHERE when you only need matching records.\n4. Add ORDER BY to make the results predictable.\n5. Add LIMIT when showing recent or top records.\n6. Test the query with a small dataset before using it in an app.",
        "SELECT name, email FROM users WHERE status = 'active' ORDER BY created_at DESC LIMIT 10 returns the ten newest active users.",
        "Write queries to list all published courses, all active users, and the five newest payments.",
        "Can you explain what each clause in your query does?"
    ), "", 2, "published", 38),
    (3, "Joins and Aggregates", lesson_content(
        "Joins and Aggregates",
        "- Combine related tables with joins\n- Count, sum, and group records\n- Create data for reports and dashboards",
        "Most useful database questions need data from more than one table. Joins connect rows using matching keys. Aggregates summarize many rows into totals, counts, or averages. GROUP BY creates one result per group, such as revenue per plan or completed lessons per course. These tools power admin dashboards and reports.",
        "1. Identify which tables contain the needed data.\n2. Find the key that connects them.\n3. Use JOIN to combine records.\n4. Use COUNT or SUM when you need totals.\n5. Use GROUP BY when you need totals per category.\n6. Verify the result by checking a few sample rows manually.",
        "A report showing active subscriptions per plan joins plans to subscriptions, filters active subscriptions, and groups by plan name.",
        "Write a query that shows each course title and the number of published lessons under it.",
        "Can you tell whether your join should be INNER JOIN or LEFT JOIN based on whether missing related records should still appear?"
    ), "", 3, "published", 42),
    (4, "Full-Stack Architecture", lesson_content(
        "Full-Stack Architecture",
        "- Understand how frontend, backend, database, and external services work together\n- Follow the request-response cycle\n- Identify where business rules belong",
        "A full-stack application has multiple layers. The frontend is what the user sees. The backend receives requests, checks permissions, applies rules, reads or writes the database, and returns a response. The database stores persistent information. External services, such as payment gateways or email providers, handle specialized tasks. A well-designed full-stack app keeps responsibilities clear.",
        "1. A user clicks a link or submits a form.\n2. The browser sends a request to the Flask backend.\n3. Flask runs the matching route function.\n4. The route validates input and checks the session.\n5. The route queries or updates the database.\n6. Flask renders a template or redirects the user.\n7. The browser displays the result.",
        "When a user subscribes, the app creates a checkout session, receives payment confirmation, records a subscription, then allows course access based on the selected plan.",
        "Draw the flow for requesting a cancellation, from user form submission to admin approval and user notification.",
        "Can you identify which layer should validate permissions and why?"
    ), "", 1, "published", 38),
    (4, "Authentication and Sessions", lesson_content(
        "Authentication and Sessions",
        "- Store passwords safely using hashes\n- Use sessions to remember logged-in users\n- Protect routes with decorators\n- Understand why server-side checks matter",
        "Authentication confirms who the user is. Passwords should never be stored as plain text. Instead, the app stores a hash. During login, the submitted password is checked against the hash. Sessions let the server remember that a browser is logged in. Decorators such as login_required and admin_required protect routes so unauthorized users cannot access private pages.",
        "1. During registration, validate the form and hash the password.\n2. During login, find the user by email.\n3. Check that the account is active.\n4. Compare the password with the stored hash.\n5. Store user id, name, and role in the session.\n6. Check the session before protected pages.\n7. Clear the session during logout.",
        "An admin page should not rely on hiding a link in the sidebar. The route itself must check that the session role is admin before showing data.",
        "Explain what could go wrong if an admin page only hides navigation links but does not check permissions in the route.",
        "Can you describe the difference between authentication and authorization?"
    ), "", 2, "published", 45),
    (4, "Admin Dashboards", lesson_content(
        "Admin Dashboards",
        "- Build dashboard cards from database queries\n- Create filters for users, payments, and subscriptions\n- Use notifications to highlight required action",
        "An admin dashboard turns raw data into decisions. Good dashboards show totals, recent activity, exceptions, and tasks that need attention. For a subscription learning platform, useful admin data includes total users, active subscriptions, revenue, failed payments, course count, pending cancellations, and recent audit logs. Notifications help admins notice time-sensitive events such as cancellation requests.",
        "1. Decide which questions the admin needs answered quickly.\n2. Write one database query per metric.\n3. Keep the dashboard readable with cards and short labels.\n4. Link summary cards to detailed pages.\n5. Add filters on detailed tables.\n6. Add notifications for important workflow events.\n7. Record admin actions in an audit log.",
        "If a user requests cancellation, the system can create a notification for every admin account. The sidebar can show a badge, and the notifications page can link directly to the cancellation review page.",
        "Design three admin notification types: cancellation request, failed payment, and new free-trial signup. Write the title, message, and destination link for each.",
        "Does each dashboard card help an admin decide what to do next?"
    ), "", 3, "published", 45),
    (5, "Cloud Deployment Overview", lesson_content(
        "Cloud Deployment Overview",
        "- Prepare an app for deployment\n- Separate secrets from code\n- Understand logs, environment variables, and production settings",
        "Deployment is the process of making an app available to real users. A development setup can be forgiving, but production needs stronger security and reliability. Secret keys, database paths, Stripe keys, and email credentials should be stored in environment variables, not hard-coded into source files. Production should disable debug mode, use secure cookies, and collect logs so errors can be investigated.",
        "1. Move secrets into a .env file or platform environment settings.\n2. Create a requirements.txt file.\n3. Use a stable database location.\n4. Turn off debug mode in production.\n5. Configure email and payment webhooks.\n6. Test registration, login, checkout, cancellation, and reports.\n7. Back up the database before major changes.",
        "A safe project repository includes .env.example to show required variables, but it does not include the real .env file containing secret keys.",
        "Create a deployment checklist for this learning platform. Include database, email OTP, Stripe, admin account, and PDF report export checks.",
        "Can the project be shared without exposing private credentials?"
    ), "", 1, "published", 38),
    (5, "CI/CD Basics", lesson_content(
        "CI/CD Basics",
        "- Understand continuous integration and continuous delivery\n- Run checks before deployment\n- Plan safe database changes and rollbacks",
        "CI/CD helps teams release software more reliably. Continuous integration runs checks when code changes, such as syntax checks or tests. Continuous delivery prepares the app for deployment after checks pass. For database-backed apps, releases must be careful because schema changes can affect existing data. A rollback plan helps recover if a deployment fails.",
        "1. Keep code in version control.\n2. Run syntax checks and tests automatically.\n3. Build the package or deployment artifact.\n4. Apply database migrations carefully.\n5. Deploy to a staging environment first when possible.\n6. Smoke-test important user flows.\n7. Keep a rollback plan and database backup.",
        "Before deploying a new lesson progress feature, you would add a progress_percent column, test old users with no progress rows, then verify that scrolling saves progress correctly.",
        "Write a release plan for adding OTP verification to registration. Include tests for valid OTP, expired OTP, wrong OTP, and duplicate email.",
        "Can you list what must be tested before users rely on the new release?"
    ), "", 2, "published", 40),
    (6, "What Is Machine Learning?", lesson_content(
        "What Is Machine Learning?",
        "- Explain how ML differs from rule-based programming\n- Understand features, labels, and training data\n- Identify common ML tasks",
        "Machine learning is a way to build systems that learn patterns from data instead of relying only on manually written rules. In rule-based software, a developer writes exact conditions. In machine learning, a model finds patterns from examples. The input information is called features. The answer the model learns to predict is often called the label. The quality of the data strongly affects the quality of the model.",
        "1. Define the problem.\n2. Collect relevant examples.\n3. Choose useful features.\n4. Split data for training and evaluation.\n5. Train a model.\n6. Measure performance.\n7. Use the model carefully and monitor results.",
        "A rule-based spam filter might block emails containing specific words. A machine learning spam filter learns from many examples of spam and non-spam emails, then predicts the probability that a new email is spam.",
        "Classify these as rule-based or machine learning: password length validation, product recommendation, email OTP expiration, handwritten digit recognition, and subscription status calculation.",
        "Can you explain why more data is not always better if the data is inaccurate or biased?"
    ), "", 1, "published", 35),
    (6, "Training and Evaluation", lesson_content(
        "Training and Evaluation",
        "- Split data into training and validation sets\n- Understand common evaluation metrics\n- Recognize overfitting and underfitting\n- Interpret model results responsibly",
        "Training is the process of letting a model learn patterns from data. Evaluation checks whether the model works on examples it has not seen before. If a model performs very well on training data but poorly on new data, it may be overfitting. If it performs poorly everywhere, it may be underfitting. Metrics such as accuracy, precision, recall, and F1 score help describe performance, but the right metric depends on the problem.",
        "1. Clean and prepare the dataset.\n2. Split the data into training and validation sets.\n3. Train the model on the training data.\n4. Predict results for validation data.\n5. Compare predictions with true labels.\n6. Review metrics and errors.\n7. Improve features, data quality, or model choice.",
        "For a medical screening model, recall may be more important than accuracy because missing a true positive case can be costly. For a recommendation model, ranking quality and user engagement may matter more than simple accuracy.",
        "Given a confusion matrix, calculate which mistakes are false positives and false negatives. Explain which mistake would be more serious for fraud detection.",
        "Can you explain why a model should be evaluated on data it did not train on?"
    ), "", 2, "published", 45),
]

c.executemany("""INSERT INTO lessons (course_id, title, content, video_url, position, status, duration_minutes) VALUES (?, ?, ?, ?, ?, ?, ?)""", lessons)

conn.commit()
conn.close()
print("Database initialized successfully with OTP, notifications, free trial, university, and lesson percentage tracking support.")
