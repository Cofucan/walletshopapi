""" Admin panel for the API. """

from typing import Sequence

import flask_admin
from fastapi import FastAPI, Request
from fastapi.middleware.wsgi import WSGIMiddleware
from flask import redirect, request, url_for, session, Flask
from flask_admin import expose, AdminIndexView
from flask_admin.contrib.sqla import ModelView
from jinja2 import Environment, FileSystemLoader
from starlette.responses import RedirectResponse, Response
from wtforms import validators
from wtforms.fields import StringField

from app.database import SessionLocal
from app.models.user_models import User
from app.services.auth_services import hash_password, verify_password
from app.settings import APP_NAME, SECRET_KEY

template_env = Environment(loader=FileSystemLoader("templates"))


class UserAdmin(ModelView):
    """User model admin view."""

    form_excluded_columns = [
        "password_hash",
    ]
    form_extra_fields = {
        "Password": StringField("Password", [validators.DataRequired()])
    }

    def on_model_change(self, form, model: User, is_created):
        hashed = hash_password(form["Password"].data)
        model.password_hash = hashed


class MyAdminIndexView(AdminIndexView):
    """Admin index view."""

    @expose("/")
    def index(self):
        """Index view."""
        print("Index view")
        if not session.get("logged_in"):
            return redirect(url_for(".login_view"))
        session.permanent = True
        return super().index()

    @expose("/login/", methods=("GET", "POST"))
    def login_view(self):
        """Login view."""
        error = None
        if request.method == "POST":
            email = request.form["email"]
            passw = request.form["password"]

            with SessionLocal() as db:
                user = db.query(User).filter_by(email=email).first()

                if not user:
                    error = "User does not exist"
                elif (not user.is_superadmin) or (user.is_superadmin is None):
                    error = "User is not an admin"
                elif verify_password(passw, user.hashed_password):
                    print("Correct credentials")
                    session["logged_in"] = True
                    session.permanent = True
                    return redirect(url_for(".index"))
                else:
                    error = "Wrong password"

        login_template = template_env.get_template("admin_login.html")

        return login_template.render(app_name=APP_NAME, error=error)

    @expose("/logout/")
    def logout_view(self):
        """Logout view."""
        session.clear()
        return redirect(url_for(".index"))


ADMIN_MODELS = [(User, UserAdmin), Category, Character]


def create_admin_app():
    """Create the admin app."""
    app = Flask(__name__)
    app.secret_key = SECRET_KEY

    admin = flask_admin.Admin(
        app,
        template_mode="bootstrap3",
        url="/",
        index_view=MyAdminIndexView(name=f"{APP_NAME} Admin", url="/"),
    )

    for model in ADMIN_MODELS:
        if isinstance(model, Sequence):
            model, view_class = model
            admin.add_view(view_class(model, SessionLocal()))
        else:
            admin.add_view(ModelView(model, SessionLocal()))

    return app


admin_app_wsgi = WSGIMiddleware(create_admin_app())

admin_app = FastAPI()


@admin_app.middleware("http")
async def admin_auth_middleware(req: Request, call_next) -> Response:
    """
    Middleware to check if the request is for the admin panel and the
    user is authenticated.
    """
    if (
        "admin" in req.url.path
        and not req.session.get("logged_in")
        and not req.url.path.endswith("/login/")
    ):
        print("Not logged in. Login first.")
        # Redirect to login
        return RedirectResponse(url="/admin/login/")
    return await call_next(req)


admin_app.mount(path="/", app=admin_app_wsgi, name="admin_app")
