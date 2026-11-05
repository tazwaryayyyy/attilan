import React, { FormEvent, useState } from 'react';
import { DocumentRecord } from '../types/evidence';

interface SoftTombstoneModalProps {
  document: DocumentRecord;
  isOpen: boolean;
  bearerToken: string;
  onClose: () => void;
  onSuccess: (updatedRecord: unknown) => void;
}

export const SoftTombstoneModal: React.FC<SoftTombstoneModalProps> = ({
  document,
  isOpen,
  bearerToken,
  onClose,
  onSuccess,
}) => {
  const [legalJustification, setLegalJustification] = useState('');
  const [dispositionDate, setDispositionDate] = useState('');
  const [newSummary, setNewSummary] = useState('');
  const [courtOrderSourceId, setCourtOrderSourceId] = useState('');
  const [newWeight, setNewWeight] = useState('JUDICIAL_ACQUITTAL');
  const [submitting, setSubmitting] = useState(false);
  const [fault, setFault] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (!bearerToken) {
      setFault('Verified bearer token required. Client-supplied actor UUIDs are rejected.');
      return;
    }

    const targetEventId = document.event_id || (document as any).event_id;
    if (!targetEventId) {
      setFault('Evidentiary violation: Target event_id is required. Submitting source_id is prohibited.');
      return;
    }

    if (!legalJustification.trim()) {
      setFault('Statutory legal justification is required. Automated defaults are rejected.');
      return;
    }

    if (!dispositionDate.trim()) {
      setFault('Court disposition date is required.');
      return;
    }

    setSubmitting(true);
    setFault(null);

    try {
      const response = await fetch(`/api/events/${targetEventId}/tombstone_and_supersede`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${bearerToken}`,
        },
        body: JSON.stringify({
          legal_justification: legalJustification,
          court_order_source_id: courtOrderSourceId,
          new_event_type: 'JUDICIAL_VERDICT',
          new_procedural_weight: newWeight,
          new_event_summary: newSummary,
          new_event_date: dispositionDate,
        }),
      });
      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.detail || `HTTP ${response.status}`);
      }
      onSuccess(await response.json());
      onClose();
    } catch (err: unknown) {
      setFault(err instanceof Error ? err.message : 'Submission failed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="modal-scrim" role="dialog" aria-modal="true" aria-labelledby="tombstone-title">
      <section className="forensic-panel modal-panel">
        <header className="panel-head">
          <div>
            <p className="eyebrow">SOFT-TOMBSTONE PROTOCOL</p>
            <h2 id="tombstone-title">CONTROLLED CORRECTION</h2>
          </div>
          <button type="button" onClick={onClose}>
            CLOSE
          </button>
        </header>

        <p className="panel-alert">
          V1 remains in the append-only sequential hash-chain ledger with is_superseded=TRUE. Active views return V2.
        </p>

        <form className="request-form stacked" onSubmit={handleSubmit}>
          <label>
            <span>STATUTORY LEGAL JUSTIFICATION</span>
            <textarea
              required
              rows={2}
              value={legalJustification}
              onChange={(e) => setLegalJustification(e.target.value)}
              placeholder="Enter authenticated judicial decree citation (human entry required)"
            />
          </label>
          <label>
            <span>DISPOSITION DATE</span>
            <input
              required
              type="date"
              value={dispositionDate}
              onChange={(e) => setDispositionDate(e.target.value)}
            />
          </label>
          <label>
            <span>NEW EVIDENTIARY WEIGHT</span>
            <select value={newWeight} onChange={(e) => setNewWeight(e.target.value)}>
              <option value="JUDICIAL_ACQUITTAL">JUDICIAL_ACQUITTAL</option>
              <option value="JUDICIAL_CONVICTION">JUDICIAL_CONVICTION</option>
            </select>
          </label>
          <label>
            <span>COURT ORDER SOURCE UUID</span>
            <input
              required
              value={courtOrderSourceId}
              onChange={(e) => setCourtOrderSourceId(e.target.value)}
              spellCheck={false}
              placeholder="00000000-0000-0000-0000-000000000000"
            />
          </label>
          <label>
            <span>ACTIVE V2 SUMMARY</span>
            <textarea
              required
              rows={3}
              value={newSummary}
              onChange={(e) => setNewSummary(e.target.value)}
              placeholder="Enter verified judicial disposition summary"
            />
          </label>

          {fault && (
            <div className="offline-block" role="alert">
              <strong>X-01 REJECTED</strong>
              <p>{fault}</p>
            </div>
          )}

          <div className="action-row">
            <button type="button" onClick={onClose}>
              CANCEL
            </button>
            <button type="submit" disabled={submitting}>
              {submitting ? 'COMMITTING…' : 'COMMIT TOMBSTONE / WRITE V2'}
            </button>
          </div>
        </form>
      </section>
    </div>
  );
};
