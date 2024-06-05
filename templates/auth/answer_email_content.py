answer_email_content = """
<p>Bonjour {{ user_email }},</p>
<p>Votre événement a été <strong>{{ answer }}</strong>.</p>
<p>Voici les détails de l'événement :</p>
<ul>
    <li><strong>Titre :</strong> {{ event_title }}</li>
    <li><strong>Type :</strong> {{ event_type }}</li>
    <li><strong>Date et heure de début :</strong> {{ event_start }}</li>
    <li><strong>Date et heure de fin :</strong> {{ event_end }}</li>
</ul>
<p>Merci de vérifier ces informations et de nous contacter si vous avez des questions.</p>
<p>Merci !</p>
"""
