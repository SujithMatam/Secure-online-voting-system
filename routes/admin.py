"""
Admin routes: Dashboard, Manage Users, Create/Manage Elections, Audit Logs.
All routes require admin role.
"""

from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from utils.decorators import admin_required
from utils.security import sanitize_input
from datetime import datetime
from bson import ObjectId
import logging
import secrets

admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/dashboard')
@admin_required
def dashboard():
    from extensions import mongo

    total_users = mongo.db.users.count_documents({'role': 'voter'})
    verified_users = mongo.db.users.count_documents({'role': 'voter', 'is_verified': True})
    active_elections = mongo.db.elections.count_documents({'status': 'active'})
    total_votes = mongo.db.votes.count_documents({})

    return render_template(
        'admin/dashboard.html',
        total_users=total_users,
        verified_users=verified_users,
        active_elections=active_elections,
        total_votes=total_votes
    )


@admin_bp.route('/users')
@admin_required
def manage_users():
    from extensions import mongo

    users = list(mongo.db.users.find({'role': 'voter'}).sort('created_at', -1))
    for u in users:
        u['_id'] = str(u['_id'])

    return render_template('admin/manage_users.html', users=users)


@admin_bp.route('/users/verify/<user_id>', methods=['POST'])
@admin_required
def verify_user(user_id):
    from extensions import mongo

    try:
        uid = ObjectId(user_id)
    except Exception:
        flash('Invalid user ID.', 'danger')
        return redirect(url_for('admin.manage_users'))

    mongo.db.users.update_one(
        {'_id': uid},
        {'$set': {'is_verified': True}}
    )

    user = mongo.db.users.find_one({'_id': uid})
    username = user['username'] if user else 'unknown'

    logging.info(f"Admin verified user: {username}")

    mongo.db.audit_log.insert_one({
        'action': 'VERIFY_USER',
        'admin_id': session['user_id'],
        'admin_username': session['username'],
        'target_user_id': user_id,
        'target_username': username,
        'ip_address': request.remote_addr,
        'timestamp': datetime.utcnow(),
        'status': 'SUCCESS'
    })

    flash(f'User {username} verified successfully.', 'success')
    return redirect(url_for('admin.manage_users'))


@admin_bp.route('/users/revoke/<user_id>', methods=['POST'])
@admin_required
def revoke_user(user_id):
    from extensions import mongo

    try:
        uid = ObjectId(user_id)
    except Exception:
        flash('Invalid user ID.', 'danger')
        return redirect(url_for('admin.manage_users'))

    mongo.db.users.update_one(
        {'_id': uid},
        {'$set': {'is_verified': False}}
    )

    user = mongo.db.users.find_one({'_id': uid})
    username = user['username'] if user else 'unknown'

    logging.info(f"Admin revoked user verification: {username}")

    mongo.db.audit_log.insert_one({
        'action': 'REVOKE_USER',
        'admin_id': session['user_id'],
        'admin_username': session['username'],
        'target_user_id': user_id,
        'target_username': username,
        'ip_address': request.remote_addr,
        'timestamp': datetime.utcnow(),
        'status': 'SUCCESS'
    })

    flash(f'User {username} verification revoked.', 'success')
    return redirect(url_for('admin.manage_users'))


@admin_bp.route('/elections/create', methods=['GET', 'POST'])
@admin_required
def create_election():
    from extensions import mongo

    if request.method == 'POST':
        title = sanitize_input(request.form.get('title', ''))
        description = sanitize_input(request.form.get('description', ''))
        candidate_names = request.form.getlist('candidate_name')
        candidate_parties = request.form.getlist('candidate_party')

        if not title:
            flash('Election title is required.', 'danger')
            return render_template('admin/create_election.html')

        if len(candidate_names) < 2:
            flash('At least 2 candidates are required.', 'danger')
            return render_template('admin/create_election.html')

        candidates = []
        for i, (name, party) in enumerate(zip(candidate_names, candidate_parties)):
            name = sanitize_input(name)
            party = sanitize_input(party)
            if name:
                candidates.append({
                    'id': secrets.token_hex(8),
                    'name': name,
                    'party': party or 'Independent'
                })

        if len(candidates) < 2:
            flash('At least 2 valid candidates are required.', 'danger')
            return render_template('admin/create_election.html')

        election = {
            'title': title,
            'description': description,
            'candidates': candidates,
            'status': 'active',
            'created_by': session['user_id'],
            'created_at': datetime.utcnow()
        }

        result = mongo.db.elections.insert_one(election)

        # Create unique index for one-person-one-vote
        mongo.db.votes.create_index(
            [('user_id', 1), ('election_id', 1)],
            unique=True
        )

        logging.info(f"Election created: {title} by admin {session['username']}")

        mongo.db.audit_log.insert_one({
            'action': 'CREATE_ELECTION',
            'admin_id': session['user_id'],
            'admin_username': session['username'],
            'election_id': str(result.inserted_id),
            'election_title': title,
            'ip_address': request.remote_addr,
            'timestamp': datetime.utcnow(),
            'status': 'SUCCESS'
        })

        flash('Election created successfully!', 'success')
        return redirect(url_for('admin.dashboard'))

    return render_template('admin/create_election.html')


@admin_bp.route('/elections')
@admin_required
def manage_elections():
    from extensions import mongo

    elections = list(mongo.db.elections.find().sort('created_at', -1))
    for e in elections:
        e['_id'] = str(e['_id'])
        e['vote_count'] = mongo.db.votes.count_documents({'election_id': e['_id']})

    return render_template('admin/manage_elections.html', elections=elections)


@admin_bp.route('/elections/end/<election_id>', methods=['POST'])
@admin_required
def end_election(election_id):
    from extensions import mongo

    try:
        eid = ObjectId(election_id)
    except Exception:
        flash('Invalid election ID.', 'danger')
        return redirect(url_for('admin.manage_elections'))

    mongo.db.elections.update_one(
        {'_id': eid},
        {'$set': {'status': 'completed', 'ended_at': datetime.utcnow()}}
    )

    logging.info(f"Election ended: {election_id} by admin {session['username']}")

    mongo.db.audit_log.insert_one({
        'action': 'END_ELECTION',
        'admin_id': session['user_id'],
        'admin_username': session['username'],
        'election_id': election_id,
        'ip_address': request.remote_addr,
        'timestamp': datetime.utcnow(),
        'status': 'SUCCESS'
    })

    flash('Election ended successfully.', 'success')
    return redirect(url_for('admin.manage_elections'))


@admin_bp.route('/audit-log')
@admin_required
def audit_log():
    from extensions import mongo

    logs = list(mongo.db.audit_log.find().sort('timestamp', -1).limit(200))
    for log in logs:
        log['_id'] = str(log['_id'])

    return render_template('admin/audit_log.html', logs=logs)
