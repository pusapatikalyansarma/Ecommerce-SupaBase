import os
import uuid
import json
from math import ceil
from pathlib import Path

import bcrypt
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, abort
)
from werkzeug.utils import secure_filename

from database import createTables, AuthQueries, AdminQueries, UserQueries
from database.connection import DatabaseConnction
from database.storage import (
    upload_product_image,
    get_product_image_url,
    delete_product_image
)
from dotenv import load_dotenv

import razorpay
from decimal import Decimal
from functools import wraps


BASE_DIR = Path(__file__).resolve().parent

load_dotenv(BASE_DIR / ".env", override=False)

app = Flask(__name__)

app.secret_key = os.getenv("FLASK_SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY is missing from .env")

key = os.getenv("RAZORPAY_KEY_ID", "")

print("ENV FILE:", BASE_DIR / ".env")
print("ENV FILE EXISTS:", (BASE_DIR / ".env").exists())
print("RAZORPAY KEY :", True if key else "MISSING")
print(
    "RAZORPAY MODE:",
    "LIVE" if key.startswith("rzp_live_") else "TEST / INVALID"
)
BASE_DIR = Path(__file__).resolve().parent
PRODUCT_IMAGE_DIR = BASE_DIR / "static" / "images" / "products"
PRODUCT_IMAGE_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "gif"}


SETTINGS_FILE = BASE_DIR / "shop_settings.json"
DEFAULT_SETTINGS = {
    "admin_name": "Admin",
    "admin_email": "",
    "shop_name": "ShopZone",
    "shop_email": "",
    "shop_phone": "",
    "currency": "INR",
    "shop_address": "",
    "default_order_status": "PENDING",
    "shipping_charge": "0.00",
}


def load_shop_settings():
    """Load editable shop settings; use defaults if the file is not present."""
    try:
        saved = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        if isinstance(saved, dict):
            return {**DEFAULT_SETTINGS, **saved}
    except (OSError, json.JSONDecodeError):
        pass
    return DEFAULT_SETTINGS.copy()


def save_shop_settings(settings):
    """Persist settings atomically to avoid a partially written JSON file."""
    temporary = SETTINGS_FILE.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(settings, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    temporary.replace(SETTINGS_FILE)


def fetch_categories():
    connection = DatabaseConnction()
    cursor = None
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("""
            SELECT c.categoryid AS id,
                   c.categoryname AS name,
                   c.description,
                   COUNT(p.productid) AS product_count
            FROM categories c
            LEFT JOIN products p ON p.category = c.categoryname
            GROUP BY c.categoryid, c.categoryname, c.description
            ORDER BY c.categoryname
        """)
        return cursor.fetchall()
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


def fetch_category_names():
    connection = None
    cursor = None

    try:
        connection = DatabaseConnction()
        cursor = connection.cursor()

        cursor.execute("""
            SELECT categoryname AS name
            FROM categories

            UNION

            SELECT category AS name
            FROM products
            WHERE category IS NOT NULL
              AND BTRIM(category) <> ''

            ORDER BY name
        """)

        return [(row[0],) for row in cursor.fetchall()]

    finally:
        if cursor:
            cursor.close()

        if connection and connection.is_connected():
            connection.close()

def login_required(role=None):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args,**kwargs):
            if not session.get('id') or not session.get('role'):
                flash('Please log in to continue.','err')
                return redirect(url_for('login',next=request.path))
            if role and session.get('role') != role:
                if role == "user" and session.get("role") == "admin":
                    flash("Checkout is available to customer accounts, not administrator accounts.", "err")
                    return redirect(url_for("admin_dashboard"))
                abort(403)
            return fn(*args,**kwargs)
        return wrapped
    return decorator

def user_required(fn): 
    return login_required('user')(fn)
def admin_required(fn):
    return login_required('admin')(fn)
def money(v): 
    return Decimal(str(v))
def cart_summary(uid):
    _, items = UserQueries.cartItems(uid)
    items=items if isinstance(items,list) else []
    subtotal=sum((money(i['subtotal']) for i in items),Decimal('0.00'))
    shipping=(subtotal*Decimal('0.01')).quantize(Decimal('0.01'))
    return items,subtotal,shipping,subtotal+shipping




def razorpay_client():
    key = (os.getenv("RAZORPAY_KEY_ID") or "").strip()
    secret = (os.getenv("RAZORPAY_KEY_SECRET") or "").strip()

    if not key or not secret:
        print("ERROR: Razorpay test credentials missing.")
        return None

    # This project is currently restricted to TEST MODE.
    if not key.startswith("rzp_test_"):
        print("ERROR: Test Mode keys required. Live payments are disabled.")
        return None

    try:
        client = razorpay.Client(auth=(key, secret))
        print("Razorpay client initialized: TEST MODE")
        return client

    except Exception as error:
        print("Razorpay initialization failed:", str(error))
        return None
    
def allowed_image(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS


def product_image_url(product):
    """Return the correct image URL from Supabase Storage or legacy local storage."""

    if not product:
        return None

    stored_path = (product.get("storedpath") or "").replace("\\", "/").strip()
    img_name = product.get("imgname") or ""

    # New images stored in Supabase Storage
    if stored_path.startswith("products/"):
        try:
            return get_product_image_url(stored_path)
        except Exception:
            app.logger.exception(
                "Failed to generate Supabase image URL: %s",
                stored_path
            )
            return None

    # Existing images stored locally
    if stored_path:
        normalized = stored_path.lstrip("/")

        if normalized.startswith("static/"):
            normalized = normalized[len("static/"):]

        if normalized.startswith("images/"):
            return url_for("static", filename=normalized)

    # Legacy fallback when only imgname is available
    if img_name:
        return url_for(
            "static",
            filename=f"images/products/{img_name}"
        )

    return None

@app.context_processor
def inject_product_helpers():
    return {"product_image_url": product_image_url}


@app.before_request
def enforce_admin_access():
    """Protect every /admin endpoint using the user's current database role."""
    if not request.path.startswith("/admin"):
        return None

    if not session.get("id") or not session.get("email"):
        flash("Please log in with an administrator account to access that page.", "err")
        return redirect(url_for("login", next=request.path))

    status, user = AuthQueries.getUserData(email=session["email"])
    if not status or not user or not user.get("is_active", 1):
        session.clear()
        flash("Your account is unavailable. Please log in again.", "err")
        return redirect(url_for("login"))

    if user.get("role") != "admin":
        flash("Access denied. Administrator privileges are required.", "err")
        return redirect(url_for("products"))

    return None


# ===============================================================
# Authentication Routes
# ===============================================================

@app.route("/")
def home():
    return render_template("home.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""

    if not email or not password:
        flash("Enter both email and password.", "err")
        return redirect(url_for("login"))

    status, user = AuthQueries.getUserData(email=email)
    if not status:
        flash("Account not found. Check the email or register first.", "err")
        return redirect(url_for("login"))

    try:
        password_matches = bcrypt.checkpw(
            password.encode("utf-8"),
            user["hashpassword"].encode("utf-8")
        )
    except (KeyError, TypeError, ValueError):
        password_matches = False

    if not password_matches:
        flash("Password incorrect.", "err")
        return redirect(url_for("login"))

    if not user.get("is_active", 1):
        flash("This account is inactive.", "err")
        return redirect(url_for("login"))

    session.clear()
    session["id"] = user["userid"]
    session["name"] = user["username"]
    session["email"] = user["email"]
    session["role"] = user["role"]

    if user["role"] == "admin":
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("products"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    name = (request.form.get("name") or "").strip()
    email = (request.form.get("email") or "").strip().lower()
    phone = (request.form.get("phone") or "").strip()
    password = request.form.get("password") or ""
    confirm_password = request.form.get("confirm_password") or ""

    if not name or not email or not password:
        flash("Name, email, and password are required.", "err")
        return redirect(url_for("register"))

    if password != confirm_password:
        flash("Passwords do not match.", "err")
        return redirect(url_for("register"))

    exists, existing_user = AuthQueries.getUserData(email=email)
    if exists:
        flash("An account with this email already exists.", "err")
        return redirect(url_for("register"))

    hashed_password = bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")

    status, message = AuthQueries.insertUserRecord(
        name=name,
        email=email,
        password=hashed_password,
        phone=phone
    )
    flash(message, "msg" if status else "err")
    return redirect(url_for("login"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "msg")
    return redirect(url_for("home"))


# ===============================================================
# Customer Product Routes
# ===============================================================

@app.route("/products")
def products():
    search_term = (request.args.get("search") or "").strip()
    selected_category = (request.args.get("category") or "").strip()

    status, all_products = AdminQueries.getAllProducts(
        productname=search_term or None,
        category=selected_category or None
    )

    if not status:
        flash(str(all_products), "err")
        all_products = []

    # Only show active products in the customer-facing store.
    visible_products = [
        product for product in all_products
        if product.get("is_active", 1)
    ]

    category_status, category_rows = AdminQueries.getAllCategories()
    if not category_status:
        category_rows = []

    categories = sorted({
        row[0] for row in category_rows
        if row and row[0]
    }, key=str.casefold)

    return render_template(
        "user/products.html",
        products=visible_products,
        categories=categories,
        search=search_term,
        selected_category=selected_category
    )


@app.route("/products/<int:product_id>")
def product_details(product_id):
    status, product = AdminQueries.getAllProducts(product_id=product_id)

    if not status:
        flash(str(product), "err")
        return redirect(url_for("products"))

    if not product or not product.get("is_active", 1):
        flash("That product could not be found.", "err")
        return redirect(url_for("products"))

    return render_template("user/product_details.html", product=product)


# ===============================================================
# Customer Cart Routes
# ===============================================================

@app.route("/cart", methods=["GET"])
def cart():
    if not session.get("id"):
        flash("Please log in to view your cart.", "err")
        return redirect(url_for("login", next=url_for("cart")))

    connection = None
    cursor = None
    cart_items = []
    total = 0.0
    try:
        connection = DatabaseConnction()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """SELECT c.cartid, c.productid, c.quantity AS cart_quantity,
                      p.productname, p.description, p.category, p.saleprice,
                      p.imgname, p.storedpath, p.quantity AS stock,
                      p.is_active
               FROM cart c
               JOIN products p ON p.productid = c.productid
               WHERE c.userid = %s
               ORDER BY c.cartid DESC""",
            (session["id"],)
        )
        rows = cursor.fetchall()
        for item in rows:
            item["subtotal"] = float(item.get("saleprice") or 0) * int(item.get("cart_quantity") or 0)
            cart_items.append(item)
            total += item["subtotal"]
    except Exception as error:
        flash(f"Could not load your cart: {error}", "err")
    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None and connection.is_connected():
            connection.close()

    return render_template("user/cart.html", cart_items=cart_items, total=total)


@app.route("/cart/add/<int:product_id>", methods=["POST"])
def add_to_cart(product_id):
    if not session.get("id"):
        flash("Please log in before adding items to your cart.", "err")
        return redirect(url_for("login", next=url_for("product_details", product_id=product_id)))

    try:
        requested_quantity = int(request.form.get("quantity", 1))
    except (TypeError, ValueError):
        requested_quantity = 1

    if requested_quantity < 1:
        flash("Quantity must be at least 1.", "err")
        return redirect(url_for("product_details", product_id=product_id))

    connection = None
    cursor = None
    try:
        connection = DatabaseConnction()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT productid, quantity, is_active FROM products WHERE productid = %s",
            (product_id,)
        )
        product = cursor.fetchone()
        if not product or not product.get("is_active", 1):
            flash("This product is not available.", "err")
            return redirect(url_for("products"))

        stock = int(product.get("quantity") or 0)
        if stock < 1:
            flash("This product is out of stock.", "err")
            return redirect(url_for("product_details", product_id=product_id))

        cursor.execute(
            "SELECT cartid, quantity FROM cart WHERE userid = %s AND productid = %s LIMIT 1",
            (session["id"], product_id)
        )
        existing = cursor.fetchone()
        current_quantity = int(existing["quantity"]) if existing else 0
        new_quantity = current_quantity + requested_quantity

        if new_quantity > stock:
            flash(f"Only {stock} item(s) are currently available.", "err")
            return redirect(url_for("product_details", product_id=product_id))

        if existing:
            cursor.execute(
                "UPDATE cart SET quantity = %s WHERE cartid = %s AND userid = %s",
                (new_quantity, existing["cartid"], session["id"])
            )
        else:
            cursor.execute(
                "INSERT INTO cart (userid, productid, quantity) VALUES (%s, %s, %s)",
                (session["id"], product_id, requested_quantity)
            )
        connection.commit()
        flash("Product added to your cart.", "msg")
    except Exception as error:
        if connection is not None:
            connection.rollback()
        flash(f"Could not add product to cart: {error}", "err")
    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None and connection.is_connected():
            connection.close()

    return redirect(url_for("cart"))


@app.route("/cart/update/<int:cart_id>", methods=["POST"])
def update_cart_item(cart_id):
    if not session.get("id"):
        return redirect(url_for("login", next=url_for("cart")))

    try:
        quantity = int(request.form.get("quantity", 1))
        if quantity < 1:
            raise ValueError("Quantity must be at least 1.")
    except ValueError:
        flash("Enter a valid quantity of at least 1.", "err")
        return redirect(url_for("cart"))

    connection = None
    cursor = None
    try:
        connection = DatabaseConnction()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """SELECT c.cartid, p.quantity AS stock
               FROM cart c JOIN products p ON p.productid = c.productid
               WHERE c.cartid = %s AND c.userid = %s""",
            (cart_id, session["id"])
        )
        item = cursor.fetchone()
        if not item:
            flash("Cart item not found.", "err")
        elif quantity > int(item.get("stock") or 0):
            flash(f"Only {int(item.get('stock') or 0)} item(s) are available.", "err")
        else:
            cursor.execute(
                "UPDATE cart SET quantity = %s WHERE cartid = %s AND userid = %s",
                (quantity, cart_id, session["id"])
            )
            connection.commit()
            flash("Cart quantity updated.", "msg")
    except Exception as error:
        if connection is not None:
            connection.rollback()
        flash(f"Could not update cart: {error}", "err")
    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None and connection.is_connected():
            connection.close()
    return redirect(url_for("cart"))


@app.route("/cart/remove/<int:cart_id>", methods=["POST"])
def remove_cart_item(cart_id):
    if not session.get("id"):
        return redirect(url_for("login", next=url_for("cart")))

    connection = None
    cursor = None
    try:
        connection = DatabaseConnction()
        cursor = connection.cursor()
        cursor.execute(
            "DELETE FROM cart WHERE cartid = %s AND userid = %s",
            (cart_id, session["id"])
        )
        connection.commit()
        flash("Item removed from your cart.", "msg")
    except Exception as error:
        if connection is not None:
            connection.rollback()
        flash(f"Could not remove cart item: {error}", "err")
    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None and connection.is_connected():
            connection.close()
    return redirect(url_for("cart"))

#checkout 
@app.route('/checkout', methods=['GET', 'POST'])
@user_required
def checkout():
    if request.method == 'GET':
        _, items = UserQueries.cartItems(user_id=session['id'])
           
        sub_total = Decimal("0.00")

        for item in items:
            sub_total += Decimal(str(item['subtotal']))

        shipping = (sub_total * Decimal("0.01")).quantize(Decimal("0.01"))
        total = (sub_total + shipping).quantize(Decimal("0.01"))

        session['total'] = str(total)
        return render_template('user/checkout.html',
                                    cart_items = items,
                                    subtotal = sub_total,
                                    shipping = shipping,
                                    total = total
                                    )
    if request.method == 'POST':
        name = request.form.get('name')
        phone = request.form.get('phone')
        address = request.form.get('address')
        city = request.form.get('city')
        state = request.form.get('state')
        pincode = request.form.get('pincode')
        payment_method = (request.form.get('payment_method') or '').strip().upper()

        # Validate required fields
        if not all([name, phone, address, city, state, pincode, payment_method]):
            flash("All fields are required", "err")
            return redirect(url_for('checkout'))

        full_address = f"{name}, {phone}, {address}, {city}, {state}, {pincode}"
        userid = session['id']
        # COD Payment
        if payment_method == 'COD':

            status, result = UserQueries.createOrder(
                userid=userid,
                address=full_address,
                payment_method='COD'
            )
            if not status:
                flash(str(result), 'err')
                return redirect(url_for('checkout'))
            
            return redirect(
            url_for(
                "order_success",
                order_id=result["order_id"]
            )
        )
        # Razorpay Payment
        elif payment_method != 'RAZORPAY':
        
            flash("Invalid payment method", "danger")
            return redirect(url_for('checkout'))
        
        else:
            client = razorpay_client()
            if client is None:
                flash(
    "Test payment configuration is incorrect. Check your Razorpay test keys.",
    "err"
)
                return redirect(url_for("checkout"))
            total = session['total']
            print("DEBUG total:", total)
            print("DEBUG total type:", type(total)) 
            amount = int((Decimal(str(total)) * Decimal("100")).quantize(Decimal("1")))

            print("Total:", total)
            print("Amount in paise:", amount)

            if amount < 100:
                flash("Minimum order amount is ₹1", "err")
                return redirect(url_for('checkout'))

            rp = client.order.create(data={
                'amount': amount,
                'currency': 'INR',
                'receipt': f'user{session["id"]}-{os.urandom(4).hex()}'
            })

            status, order = UserQueries.createOrder(
                userid=session['id'],
                address=full_address,
                payment_method='RAZORPAY',
                razorpay_order_id=rp['id']
            )

            if not status:
                flash(str(order), 'err')
                return redirect(url_for('checkout'))

            session['pending_order_id'] = order['order_id']

            _, user = AuthQueries.getUserData(session['email'])

            return render_template(
                'user/payment.html',
                amount=amount,
                razorpay_key_id=os.getenv('RAZORPAY_KEY_ID'),
                razorpay_order=rp,
                user=user or {}
            )

@app.route('/payment/cancel', methods=['POST'])
def payment_cancel():
    if not session.get('id'):
        return redirect(url_for('login'))

    flash("Payment was cancelled.", "err")
    return redirect(url_for('cart'))
@app.route('/payment/verify', methods=['POST'])
@user_required
def verify_payment():
    try:
        payment_id = request.form.get('razorpay_payment_id')
        razorpay_order_id = request.form.get('razorpay_order_id')
        signature = request.form.get('razorpay_signature')

        if not all([payment_id, razorpay_order_id, signature]):
            flash("Missing payment verification details.", "err")
            return redirect(url_for('cart'))

        client = razorpay_client()

        if client is None:
            flash("Payment service unavailable.", "err")
            return redirect(url_for('cart'))

        # Verify Razorpay signature
        client.utility.verify_payment_signature({
            'razorpay_order_id': razorpay_order_id,
            'razorpay_payment_id': payment_id,
            'razorpay_signature': signature
        })

        # Verify that this Razorpay order belongs to this user
        connection = DatabaseConnction()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT paymentid, orderid
            FROM payments
            WHERE userid = %s
              AND razorpay_order_id = %s
              AND status = 'pending'
            LIMIT 1
        """, (session['id'], razorpay_order_id))

        payment = cursor.fetchone()

        if not payment:
            connection.close()
            flash("Payment order not found or already processed.", "err")
            return redirect(url_for('cart'))

        cursor.execute("""
            UPDATE payments
            SET status = 'success',
                razorpay_payment_id = %s
            WHERE paymentid = %s
        """, (payment_id, payment['paymentid']))

        # Save the order ID before closing the database connection.
        completed_order_id = payment["orderid"]

        connection.commit()

        cursor.close()
        connection.close()

        session.pop("pending_order_id", None)

        return redirect(
            url_for(
                "order_success",
                order_id=completed_order_id
            )
        )

    except razorpay.errors.SignatureVerificationError:
        flash("Invalid payment signature.", "err")
        return redirect(url_for('cart'))

    except Exception as e:
        print("Payment verification error:", str(e))
        flash("Payment verification failed.", "err")
        return redirect(url_for('cart'))
    
@app.route('/payment/failed', methods=['POST'])
@user_required
def payment_failed():
    razorpay_order_id = request.form.get('order_id')
    reason = request.form.get('reason', 'Payment failed')

    connection = None
    cursor = None

    try:
        connection = DatabaseConnction()
        cursor = connection.cursor()

        cursor.execute("""
            UPDATE payments
            SET status = 'failed'
            WHERE userid = %s
              AND razorpay_order_id = %s
              AND status = 'pending'
        """, (session['id'], razorpay_order_id))

        connection.commit()

    except Exception as e:
        if connection:
            connection.rollback()
        print("Payment failure update error:", str(e))

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return render_template(
        'user/payment_failed.html',
        message=reason
    )

# ===============================================================
# ORDER CONFIRMATION AND INVOICE
# ===============================================================

@app.route("/order/success/<int:order_id>")
@login_required()
def order_success(order_id):

    user_id = None if session.get("role") == "admin" else session["id"]

    status, result = AdminQueries.getOrderInvoice(
        order_id,
        user_id=user_id
    )

    if not status:
        flash(str(result), "err")

        if session.get("role") == "admin":
            return redirect(url_for("admin_orders"))

        return redirect(url_for("index"))

    order = result["order"]

    payment_success = (
        str(order.get("payment_status") or "").lower() == "success"
    )

    is_cod = order.get("payment_method") == "cash"

    return render_template(
        "user/order_success.html",
        order=order,
        is_cod=is_cod,
        payment_success=payment_success
    )


@app.route("/invoice/<int:order_id>")
@login_required()
def order_invoice(order_id):

    user_id = None if session.get("role") == "admin" else session["id"]

    status, result = AdminQueries.getOrderInvoice(
        order_id,
        user_id=user_id
    )

    if not status:
        flash(str(result), "err")

        if session.get("role") == "admin":
            return redirect(url_for("admin_orders"))

        return redirect(url_for("index"))
    
    return render_template(
    "user/invoice.html",
    order=result["order"],
    items=result["items"],
    settings=load_shop_settings()
)

# ===============================================================
# Admin Routes
# ===============================================================

@app.route("/admin/dashboard")
def admin_dashboard():

    total_products = 0
    total_categories = 0
    total_orders = 0
    total_users = 0
    recent_count = 0
    recent_orders = []

    try:
        ok, products = AdminQueries.getAllProducts()
        if ok:
            total_products = len(products or [])

        ok, categories = AdminQueries.getAllCategories()
        if ok:
            total_categories = len(categories or [])

        ok, users = AdminQueries.getAllUsers()
        if ok:
            total_users = len(users or [])

        ok, order_data = AdminQueries.getDashboardOrderData()

        if ok:
            total_orders = order_data["total_orders"]
            recent_count = order_data["recent_count"]
            recent_orders = order_data["recent_orders"]
        else:
            flash(str(order_data), "err")

    except Exception as error:
        app.logger.exception("Dashboard loading failed")
        flash(f"Dashboard error: {error}", "err")

    return render_template(
        "admin/dashboard.html",
        total_products=total_products,
        total_categories=total_categories,
        total_orders=total_orders,
        total_users=total_users,
        recent_count=recent_count,
        recent_orders=recent_orders
    )

@app.route("/admin/products")
def admin_products():
    search_term = (request.args.get("search") or "").strip()
    category = (request.args.get("category") or "").strip()

    status, product_rows = AdminQueries.getAllProducts(
        productname=search_term or None,
        category=category or None
    )
    if not status:
        flash(str(product_rows), "err")
        product_rows = []

    category_status, category_rows = AdminQueries.getAllCategories()
    categories = [row[0] for row in category_rows] if category_status else []

    return render_template(
        "admin/products.html",
        products=product_rows,
        total=len(product_rows),
        total_pages=1,
        page=1,
        per_page=max(len(product_rows), 1),
        search=search_term,
        category=category,
        categories=categories,
        status="",
        stock="",
        min_price=None,
        max_price=None
    )


@app.route("/admin/products/add-product", methods=["GET", "POST"])
def admin_add_product():
    if request.method == "GET":
        try:
            categories = fetch_category_names()
        except Exception as error:
            app.logger.exception("Could not load categories")
            flash(f"Could not load categories: {error}", "err")
            categories = []
        return render_template("admin/add_product.html", categories=categories)

    name = (request.form.get("name") or "").strip()
    selected_category = (request.form.get("category") or "").strip()
    new_category = (request.form.get("new_category") or "").strip()

    category = selected_category or new_category
    price = request.form.get("price")
    stock = request.form.get("stock")
    description = (request.form.get("description") or "").strip()
    image = request.files.get("image")
    if new_category and not selected_category:
        connection = None
        cursor = None

        try:
            connection = DatabaseConnction()
            cursor = connection.cursor()

            cursor.execute("""
                INSERT INTO categories (categoryname)
                VALUES (%s)
                ON CONFLICT (categoryname) DO NOTHING
            """, (new_category,))

            connection.commit()

        except Exception:
            if connection:
                connection.rollback()
            raise

        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    if not name or not category or price is None or stock is None:
        flash("Product name, category, price, and stock are required.", "err")
        return redirect(url_for("admin_add_product"))

    if not image or not image.filename:
        flash("Choose a product image.", "err")
        return redirect(url_for("admin_add_product"))

    if not allowed_image(image.filename):
        flash("Image must be PNG, JPG, JPEG, WEBP, or GIF.", "err")
        return redirect(url_for("admin_add_product"))

    try:
        price_value = float(price)
        stock_value = int(stock)
        if price_value < 0 or stock_value < 0:
            raise ValueError("Price and stock cannot be negative.")
    except ValueError:
        flash("Enter a valid non-negative price and stock quantity.", "err")
        return redirect(url_for("admin_add_product"))

    uploaded_path = None

    try:
        # Upload image to Supabase Storage
        uploaded_path = upload_product_image(image)

        # Keep the filename separately for the existing database column
        stored_name = uploaded_path.rsplit("/", 1)[-1]
        stored_path = uploaded_path

        # Save product details and Supabase storage path in PostgreSQL
        status, message = AdminQueries.insertProductRecord(
            product_data=(
                name, description, category, stock_value,
                price_value, stored_name, stored_path
            )
        )

        # Remove uploaded image if the database insert failed
        if not status:
            delete_product_image(uploaded_path)

        flash(message, "msg" if status else "err")

    except Exception as error:
        app.logger.exception("Failed to add product")

        # Prevent orphaned files in Supabase Storage
        if uploaded_path:
            try:
                delete_product_image(uploaded_path)
            except Exception:
                app.logger.exception("Could not clean up uploaded product image")

        flash(f"Could not add product: {error}", "err")

    return redirect(url_for("admin_products"))

@app.route("/admin/products/<int:product_id>/edit-product", methods=["GET", "POST"])
def admin_edit_product(product_id):
    status, product = AdminQueries.getAllProducts(product_id=product_id)
    if not status:
        flash(str(product), "err")
        return redirect(url_for("admin_products"))
    if not product:
        abort(404)

    if request.method == "GET":
        try:
            categories = fetch_category_names()
        except Exception as error:
            app.logger.exception("Could not load categories")
            flash(f"Could not load categories: {error}", "err")
            categories = []
        return render_template(
            "admin/edit_product.html",
            product=product,
            categories=categories
        )

    name = (request.form.get("name") or "").strip()
    category = (request.form.get("category") or "").strip()
    price = request.form.get("price")
    stock = request.form.get("stock")
    description = (request.form.get("description") or "").strip()
    image = request.files.get("image")

    if not name or not category or price is None or stock is None:
        flash("Product name, category, price, and stock are required.", "err")
        return redirect(url_for("admin_edit_product", product_id=product_id))

    try:
        price_value = float(price)
        stock_value = int(stock)
        if price_value < 0 or stock_value < 0:
            raise ValueError("Price and stock cannot be negative.")
    except ValueError:
        flash("Enter a valid non-negative price and stock quantity.", "err")
        return redirect(url_for("admin_edit_product", product_id=product_id))

    
    stored_name = product.get("imgname") or ""
    stored_path = product.get("storedpath") or ""

    old_stored_path = stored_path
    new_uploaded_path = None

    try:
        # Upload a replacement only if the admin selected a new image
        if image and image.filename:
            new_uploaded_path = upload_product_image(image)

            stored_name = new_uploaded_path.rsplit("/", 1)[-1]
            stored_path = new_uploaded_path

        status, message = AdminQueries.updateProductRecord(
            product_data=(
                name, description, category, stock_value,
                price_value, stored_name, stored_path, product_id
            )
        )

        if not status:
            # Database update failed. Keep the old image and remove the new one.
            if new_uploaded_path:
                delete_product_image(new_uploaded_path)

            flash(message, "err")
            return redirect(
                url_for("admin_edit_product", product_id=product_id)
            )

        # Database update succeeded. Now remove the previous Supabase image.
        if (
            new_uploaded_path
            and old_stored_path
            and old_stored_path.startswith("products/")
        ):
            try:
                delete_product_image(old_stored_path)
            except Exception:
                app.logger.exception(
                    "Could not delete previous product image: %s",
                    old_stored_path
                )

        flash(message, "msg")

    except Exception as error:
        app.logger.exception("Failed to update product")

        # Clean up the newly uploaded image if the operation failed.
        if new_uploaded_path:
            try:
                delete_product_image(new_uploaded_path)
            except Exception:
                app.logger.exception(
                    "Could not clean up replacement product image"
                )

        flash(f"Could not update product: {error}", "err")

    return redirect(url_for("admin_products"))
    if image and image.filename:
        if not allowed_image(image.filename):
            flash("Image must be PNG, JPG, JPEG, WEBP, or GIF.", "err")
            return redirect(url_for("admin_edit_product", product_id=product_id))
        stored_name = f"{uuid.uuid4().hex}_{secure_filename(image.filename)}"
        image.save(PRODUCT_IMAGE_DIR / stored_name)
        stored_path = str(Path("static") / "images" / "products" / stored_name)

    status, message = AdminQueries.updateProductRecord(
        product_data=(
            name, description, category, stock_value,
            price_value, stored_name, stored_path, product_id
        )
    )
    flash(message, "msg" if status else "err")
    return redirect(url_for("admin_products"))


@app.route(
    "/admin/products/<int:product_id>/deactivate",
    methods=["POST"]
)
def admin_deactivate_product(product_id):

    connection = None
    cursor = None

    try:
        connection = DatabaseConnction()
        cursor = connection.cursor()

        cursor.execute("""
            UPDATE products
            SET is_active = FALSE
            WHERE productid = %s
        """, (product_id,))

        if cursor.rowcount == 0:
            flash("Product not found or already inactive.", "err")
        else:
            connection.commit()
            flash("Product deactivated successfully.", "msg")

    except Exception as error:
        if connection:
            connection.rollback()

        app.logger.exception("Product deactivation failed")
        flash(f"Could not deactivate product: {error}", "err")

    finally:
        if cursor:
            cursor.close()

        if connection and connection.is_connected():
            connection.close()

    return redirect(url_for("admin_products"))


@app.route(
    "/admin/products/<int:product_id>/activate",
    methods=["POST"]
)
def admin_activate_product(product_id):

    connection = None
    cursor = None

    try:
        connection = DatabaseConnction()
        cursor = connection.cursor()

        cursor.execute("""
            UPDATE products
            SET is_active = TRUE
            WHERE productid = %s
        """, (product_id,))

        if cursor.rowcount == 0:
            flash("Product not found or already active.", "err")
        else:
            connection.commit()
            flash("Product activated successfully.", "msg")

    except Exception as error:
        if connection:
            connection.rollback()

        app.logger.exception("Product activation failed")
        flash(f"Could not activate product: {error}", "err")

    finally:
        if cursor:
            cursor.close()

        if connection and connection.is_connected():
            connection.close()

    return redirect(url_for("admin_products"))


@app.route("/admin/category")
def admin_category():
    try:
        categories = fetch_categories()
    except Exception as error:
        app.logger.exception("Category page failed")
        flash(f"Could not load categories: {error}", "err")
        categories = []
    return render_template("admin/category.html", categories=categories)


@app.route("/admin/category/add", methods=["POST"])
def admin_add_category():
    name = (request.form.get("name") or "").strip()
    description = (request.form.get("description") or "").strip()
    if not name:
        flash("Category name is required.", "err")
        return redirect(url_for("admin_category"))

    connection = None
    cursor = None
    try:
        connection = DatabaseConnction()
        cursor = connection.cursor()
        
        cursor.execute(
            "INSERT INTO categories (categoryname, description) VALUES (%s, %s)",
            (name, description or None)
        )
        connection.commit()
        flash("Category created successfully.", "msg")
    except Exception as error:
        if connection:
            connection.rollback()
        app.logger.exception("Category insert failed")
        flash("Could not add category. It may already exist. " + str(error), "err")
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()
    return redirect(url_for("admin_category"))


@app.route(
    "/admin/category/<int:category_id>/edit",
    methods=["GET", "POST"]
)
def admin_edit_category(category_id):

    connection = None
    cursor = None

    try:
        connection = DatabaseConnction()
        cursor = connection.cursor(dictionary=True)

        

        # Always fetch the category using its permanent ID.
        cursor.execute("""
            SELECT
                categoryid AS id,
                categoryname AS name,
                description
            FROM categories
            WHERE categoryid = %s
        """, (category_id,))

        category = cursor.fetchone()

        if not category:
            flash("Category not found.", "err")
            return redirect(url_for("admin_category"))

        if request.method == "POST":

            name = (request.form.get("name") or "").strip()
            description = (
                request.form.get("description") or ""
            ).strip()

            if not name:
                flash("Category name is required.", "err")
                return redirect(
                    url_for(
                        "admin_edit_category",
                        category_id=category_id
                    )
                )

            # Check duplicate category names.
            cursor.execute("""
                SELECT categoryid
                FROM categories
                WHERE categoryname = %s
                  AND categoryid != %s
            """, (name, category_id))

            duplicate = cursor.fetchone()

            if duplicate:
                flash(
                    "A category with this name already exists.",
                    "err"
                )
                return redirect(
                    url_for(
                        "admin_edit_category",
                        category_id=category_id
                    )
                )

            old_name = category["name"]

            # Update category.
            cursor.execute("""
                UPDATE categories
                SET categoryname = %s,
                    description = %s
                WHERE categoryid = %s
            """, (name, description or None, category_id))

            # Update associated products.
            cursor.execute("""
                UPDATE products
                SET category = %s
                WHERE category = %s
            """, (name, old_name))

            connection.commit()

            flash("Category updated successfully.", "msg")

            return redirect(url_for("admin_category"))

        return render_template(
            "admin/edit_category.html",
            category=category
        )

    except Exception as error:

        if connection:
            connection.rollback()

        app.logger.exception("Category editing failed")

        flash(
            f"Could not update category: {error}",
            "err"
        )

        return redirect(url_for("admin_category"))

    finally:

        if cursor:
            cursor.close()

        if connection and connection.is_connected():
            connection.close()


@app.route(
    "/admin/category/<int:category_id>/delete",
    methods=["POST"]
)
def admin_delete_category(category_id):

    connection = None
    cursor = None

    try:
        connection = DatabaseConnction()
        cursor = connection.cursor(dictionary=True)

        

        cursor.execute("""
            SELECT categoryid, categoryname
            FROM categories
            WHERE categoryid = %s
        """, (category_id,))

        category = cursor.fetchone()

        if not category:
            flash("Category not found.", "err")
            return redirect(url_for("admin_category"))

        category_name = category["categoryname"]

        # Preserve products, but remove their category assignment.
        cursor.execute("""
            UPDATE products
            SET category = NULL
            WHERE category = %s
        """, (category_name,))

        # Delete only the category record.
        cursor.execute("""
            DELETE FROM categories
            WHERE categoryid = %s
        """, (category_id,))

        connection.commit()

        flash(
            f"Category '{category_name}' deleted successfully. "
            "Products have been preserved.",
            "msg"
        )

    except Exception as error:

        if connection:
            connection.rollback()

        app.logger.exception("Category deletion failed")

        flash(
            f"Could not delete category: {error}",
            "err"
        )

    finally:

        if cursor:
            cursor.close()

        if connection and connection.is_connected():
            connection.close()

    return redirect(url_for("admin_category"))

@app.route("/admin/settings", methods=["GET", "POST"])
def admin_settings():
    settings = load_shop_settings()
    if request.method == "POST":
        # Each settings card submits only its own fields; preserve the rest.
        allowed_fields = set(DEFAULT_SETTINGS)
        for field in allowed_fields:
            if field in request.form:
                settings[field] = request.form.get(field, "").strip()

        if settings.get("currency") not in {"INR", "USD"}:
            settings["currency"] = "INR"
        try:
            shipping = Decimal(str(settings.get("shipping_charge", "0")))
            if shipping < 0:
                raise ValueError
            settings["shipping_charge"] = str(shipping.quantize(Decimal("0.01")))
        except Exception:
            flash("Shipping charge must be a valid non-negative amount.", "err")
            return render_template("admin/settings.html", settings=settings)

        try:
            save_shop_settings(settings)
            flash("Settings saved successfully.", "msg")
        except OSError as error:
            app.logger.exception("Settings save failed")
            flash(f"Could not save settings: {error}", "err")
        return redirect(url_for("admin_settings"))

    return render_template("admin/settings.html", settings=settings)


@app.route("/admin/orders")
def admin_orders():

    search = (request.args.get("search") or "").strip().lower()
    status_filter = (request.args.get("status") or "").strip().upper()

    try:
        page = max(int(request.args.get("page", 1)), 1)
    except (TypeError, ValueError):
        page = 1

    per_page = 10

    status, all_orders = AdminQueries.getAllOrders()

    if not status:
        flash(str(all_orders), "err")
        all_orders = []

    # Apply search filter
    if search:
        all_orders = [
            order for order in all_orders
            if search in str(order.get("orderid", "")).lower()
            or search in str(order.get("customer_name", "")).lower()
            or search in str(order.get("customer_email", "")).lower()
        ]

    # Apply order status filter
    if status_filter:
        all_orders = [
            order for order in all_orders
            if str(order.get("status", "")).upper() == status_filter
        ]

    total = len(all_orders)

    total_pages = max(1, ceil(total / per_page))

    page = min(page, total_pages)

    start = (page - 1) * per_page
    end = start + per_page

    orders = all_orders[start:end]

    return render_template(
        "admin/orders.html",
        orders=orders,
        total=total,
        total_pages=total_pages,
        page=page,
        per_page=per_page
    )


@app.route("/admin/orders/<int:order_id>/details")
def admin_order_details(order_id):

    status, result = AdminQueries.getOrderDetails(order_id)

    if not status:
        flash(str(result), "err")
        return redirect(url_for("admin_orders"))

    return render_template(
        "admin/order_details.html",
        order=result["order"],
        order_items=result["items"]
    )



@app.route(
    "/admin/orders/<int:order_id>/edit",
    methods=["GET", "POST"]
)
def admin_edit_order(order_id):

    if request.method == "POST":

        new_status = (
            request.form.get("status") or ""
        ).strip().lower()

        allowed_statuses = {
            "pending",
            "shipped",
            "delivered",
            "cancelled"
        }

        if new_status not in allowed_statuses:
            flash("Invalid delivery status.", "err")
            return redirect(
                url_for("admin_edit_order", order_id=order_id)
            )

        status, message = AdminQueries.updateOrderStatus(
            order_id,
            new_status
        )

        flash(message, "msg" if status else "err")

        if status:
            return redirect(
                url_for("admin_order_details", order_id=order_id)
            )

        return redirect(
            url_for("admin_edit_order", order_id=order_id)
        )

    status, result = AdminQueries.getOrderDetails(order_id)

    if not status:
        flash(str(result), "err")
        return redirect(url_for("admin_orders"))

    return render_template(
        "admin/order_edit.html",
        order=result["order"]
    )

@app.route("/admin/users")
def admin_users():
    status, users = AdminQueries.getAllUsers()
    if not status:
        flash(str(users), "err")
        users = []
    return render_template("admin/users.html", users=users)


@app.route("/admin/users/<int:user_id>/details")
def admin_user_details(user_id):
    flash("User details are not implemented in this project yet.", "err")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
def admin_edit_user(user_id):
    flash("User editing is not implemented in this project yet.", "err")
    return redirect(url_for("admin_users"))


if __name__ == "__main__":
    print(createTables())
    app.run(debug=True)
