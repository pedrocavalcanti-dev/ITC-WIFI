from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password


USERNAME_FIELD = User._meta.get_field(User.USERNAME_FIELD)


class LoginForm(forms.Form):
    username = forms.CharField(label="Usuário", max_length=USERNAME_FIELD.max_length)
    password = forms.CharField(label="Senha", strip=False, widget=forms.PasswordInput)


class CadastroForm(forms.Form):
    username = forms.CharField(
        label="Usuário", max_length=USERNAME_FIELD.max_length,
        validators=USERNAME_FIELD.validators,
    )
    password = forms.CharField(label="Senha", strip=False, widget=forms.PasswordInput)

    def clean_username(self):
        username = User.normalize_username(self.cleaned_data["username"].strip())
        USERNAME_FIELD.clean(username, None)
        if User.objects.filter(**{User.USERNAME_FIELD: username}).exists():
            raise forms.ValidationError("Este usuário já existe.")
        return username

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("password"):
            user = User(**{User.USERNAME_FIELD: cleaned.get("username", "")})
            try:
                validate_password(cleaned["password"], user=user)
            except forms.ValidationError as error:
                self.add_error("password", error)
        return cleaned

    def save(self):
        if not self.is_valid():
            raise ValueError("Não é possível salvar um cadastro inválido.")
        return User.objects.create_user(
            **{User.USERNAME_FIELD: self.cleaned_data["username"]},
            password=self.cleaned_data["password"], is_active=True,
        )
