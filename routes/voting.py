"""
Voting routes: Dashboard, Cast Vote, Receipt, Results.
Security features:
  - One-person-one-vote enforcement (DB unique index)
  - Vote integrity verification (SHA-256 hashing)
  - Vote receipts for auditability
  - Rate limiting on vote casting
  - CSRF protection on vote forms
  - Input sanitization and type checking
  - Race condition prevention (double-check before insert)
"""

from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from extensions import mongo, limiter
from utils.decorators import login_required, verified_required
from utils.security import generate_vote_hash, generate_vote_receipt, sanitize_input
from datetime import datetime
from bson import ObjectId
import logging

voting_bp = Blueprint('voting', __name__)


@voting_bp.route('/dashboard')
@login_required
def dashboard():
    elections = list(mongo.db.elections.find({'status': 'active'}))
    user_id = session['user_id']

    # Check which elections the user has already voted in
    user_votes = list(mongo.db.votes.find({'user_id': user_id}))
    voted_elections = {v['election_id'] for v in user_votes}

    for election in elections:
        election['_id'] = str(election['_id'])
        election['has_voted'] = election['_id'] in voted_elections

    completed = list(mongo.db.elections.find({'status': 'completed'}))
    for e in completed:
        e['_id'] = str(e['_id'])

    return render_template(
        'voting/dashboard.html',
        elections=elections,
        completed_elections=completed,
        is_verified=session.get('is_verified', False)
    )


@voting_bp.route('/cast/<election_id>', methods=['GET', 'POST'])
@login_required
@verified_required
@limiter.limit("10 per minute")  # Rate limit: prevent vote manipulation attempts
def cast_vote(election_id):
    # --- Input validation: sanitize election_id ---
    if not isinstance(election_id, str):
        flash('Invalid election ID.', 'danger')
        return redirect(url_for('voting.dashboard'))

    try:
        eid = ObjectId(election_id)
    except Exception:
        flash('Invalid election ID format.', 'danger')
        return redirect(url_for('voting.dashboard'))

    election = mongo.db.elections.find_one({'_id': eid, 'status': 'active'})

    if not election:
        flash('Election not found or not active.', 'danger')
        return redirect(url_for('voting.dashboard'))

    user_id = session['user_id']

    # --- One-person-one-vote check ---
    existing_vote = mongo.db.votes.find_one({
        'user_id': user_id,
        'election_id': election_id
    })

    if existing_vote:
        flash('You have already voted in this election.', 'warning')
        return redirect(url_for('voting.dashboard'))

    if request.method == 'POST':
        candidate_id = sanitize_input(request.form.get('candidate', ''))

        # --- Input validation ---
        if not candidate_id or not isinstance(candidate_id, str):
            flash('Please select a candidate.', 'danger')
            election['_id'] = str(election['_id'])
            return render_template('voting/vote.html', election=election)

        # Validate candidate exists in election
        valid_candidates = [c['id'] for c in election['candidates']]
        if candidate_id not in valid_candidates:
            flash('Invalid candidate selection.', 'danger')
            logging.warning(f"Invalid candidate by user {user_id} in election {election_id}")
            election['_id'] = str(election['_id'])
            return render_template('voting/vote.html', election=election)

        # --- Race condition prevention: double-check before insert ---
        existing = mongo.db.votes.find_one({
            'user_id': user_id,
            'election_id': election_id
        })
        if existing:
            flash('You have already voted in this election.', 'warning')
            return redirect(url_for('voting.dashboard'))

        # --- Vote integrity: SHA-256 hash ---
        timestamp = datetime.utcnow()
        vote_receipt = generate_vote_receipt()
        vote_hash = generate_vote_hash(user_id, election_id, candidate_id, str(timestamp))

        vote = {
            'user_id': user_id,
            'election_id': election_id,
            'candidate_id': candidate_id,
            'timestamp': timestamp,
            'vote_hash': vote_hash,
            'vote_receipt': vote_receipt,
            'ip_address': request.remote_addr
        }

        try:
            # Unique compound index enforces one-person-one-vote at DB level
            mongo.db.votes.insert_one(vote)
        except Exception as e:
            flash('Error casting vote. You may have already voted.', 'danger')
            logging.error(f"Vote insert error: {e}")
            return redirect(url_for('voting.dashboard'))

        logging.info(f"Vote cast: user={user_id} election={election_id} receipt={vote_receipt}")

        # Audit log
        mongo.db.audit_log.insert_one({
            'action': 'VOTE_CAST',
            'user_id': user_id,
            'username': session['username'],
            'election_id': election_id,
            'vote_hash': vote_hash,
            'ip_address': request.remote_addr,
            'timestamp': timestamp,
            'status': 'SUCCESS'
        })

        flash(f'Vote cast successfully! Receipt: {vote_receipt}', 'success')
        return redirect(url_for('voting.receipt', receipt=vote_receipt))

    election['_id'] = str(election['_id'])
    return render_template('voting/vote.html', election=election)


@voting_bp.route('/receipt/<receipt>')
@login_required
def receipt(receipt):
    vote = mongo.db.votes.find_one({
        'vote_receipt': sanitize_input(receipt),
        'user_id': session['user_id']
    })

    if not vote:
        flash('Vote receipt not found.', 'danger')
        return redirect(url_for('voting.dashboard'))

    election = mongo.db.elections.find_one({'_id': ObjectId(vote['election_id'])})

    return render_template('voting/receipt.html', vote=vote, election=election)


@voting_bp.route('/results/<election_id>')
@login_required
def results(election_id):
    try:
        eid = ObjectId(election_id)
    except Exception:
        flash('Invalid election ID.', 'danger')
        return redirect(url_for('voting.dashboard'))

    election = mongo.db.elections.find_one({'_id': eid})

    if not election:
        flash('Election not found.', 'danger')
        return redirect(url_for('voting.dashboard'))

    # Only show results for completed elections (admin can always see)
    if election['status'] != 'completed' and session.get('role') != 'admin':
        flash('Results available only after the election ends.', 'warning')
        return redirect(url_for('voting.dashboard'))

    vote_results = {}
    for candidate in election['candidates']:
        count = mongo.db.votes.count_documents({
            'election_id': str(election['_id']),
            'candidate_id': candidate['id']
        })
        vote_results[candidate['id']] = {
            'name': candidate['name'],
            'party': candidate.get('party', 'Independent'),
            'votes': count
        }

    total_votes = sum(r['votes'] for r in vote_results.values())
    election['_id'] = str(election['_id'])

    return render_template(
        'voting/results.html',
        election=election,
        results=vote_results,
        total_votes=total_votes
    )
