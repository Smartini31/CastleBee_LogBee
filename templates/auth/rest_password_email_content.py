reset_password_email_html_content = """
<p>Bonjour,</p>
<p>Vous recevez cet e-mail car vous avez demandé une réinitialisation de mot de passe pour votre compte.</p>
<p>
    Pour réinitialiser votre mot de passe coller le lien ci dessous apres le '.io' de l'URL: <br>
    {{ reset_password_url }}
</p>
<p>Si vous n'avez pas demandé de réinitialisation de mot de passe, veuillez contacter quelqu'un de l'équipe de développement.</p>
<p>
    Merci !
</p>
"""