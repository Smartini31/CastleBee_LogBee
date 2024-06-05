notification_email_html_content = """
<p>Bonjour Admin,</p>
<p>Un nouvel événement a été créé par <strong>{{ user_email }}</strong>.</p>
<p>Voici les détails de l'événement :</p>
<ul>
    <li><strong>Titre :</strong> {{ event_title }}</li>
    <li><strong>Type :</strong> {{ event_type }}</li>
    <li><strong>Date et heure de début :</strong> {{ event_start }}</li>
    <li><strong>Date et heure de fin :</strong> {{ event_end }}</li>
</ul>
<p>Merci de bien vouloir examiner et traiter cet événement dès que possible <a href="http://127.0.0.1:5000/login">ici</a>.</p>
<p>Merci !</p>
"""