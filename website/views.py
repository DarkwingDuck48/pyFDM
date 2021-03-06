from flask import Blueprint, render_template, request, flash, jsonify
from flask_login import login_required,  current_user
import json
from .models import Note
from . import db


views = Blueprint('views', __name__)

@views.route('/', methods=['GET', 'POST'])
@login_required
def homepage():
    """Return homepage"""
    if request.method == "POST":
        note:str = request.form.get('note')

        if len(note) < 1:
            flash('Note is to short!', category='error')
        else:
            new_note = Note(note_text=note, user_id=current_user.id)
            db.session.add(new_note)
            db.session.commit()
            flash('Note added!', category='success')
    return render_template("home.html", user=current_user)

@views.route('/delete-note', methods=["POST"])
def delete_note():
    """Delete note for current user"""
    data = json.loads(request.data)
    noteId = data['noteId']
    note = Note.query.get(noteId)

    if note:
        if note.user_id == current_user.id:
            db.session.delete(note)
            db.session.commit()
    
    return jsonify({})