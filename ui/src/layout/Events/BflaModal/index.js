import React, { useEffect } from 'react';
import Modal from 'components/Modal';
import { useFetch, FETCH_METHODS } from 'hooks';
import Loader from 'components/Loader';

const BflaModal = ({event, type, nameSpace, onClose, onSuccess}) => {
    const [{loading: updatePending, data: updateData, error: updateError }, updateBflaWarning] = useFetch(`authorizationModel/trace`, {loadOnMount: false});

    useEffect(() => {
        if (updateData) {
            onClose();
            onSuccess();
        }
    }, [updateData, onSuccess, onClose]);

    const fetchModelAndUpdate = () => {
        const {id} = event;
        if (type === 'approve') {
            updateBflaWarning({
                formatUrl: (url) => `${url}/${id}/approve`,
                method: FETCH_METHODS.PUT
            });
        } else if (type === 'deny') {
            updateBflaWarning({
                formatUrl: (url) => `${url}/${id}/deny`,
                method: FETCH_METHODS.PUT
            });
        }
    };

    const titleType = type === 'approve' ? 'Disable' : 'Enable';
    const loading = updatePending;
    const el = document.querySelector('Main');
    const top = el.scrollTop;

    return (
        <Modal
            title={`${titleType} BFLA Warning`}
            height={230}
            onClose={onClose}
            doneTitle="Yes"
            onDone={() => fetchModelAndUpdate()}
            top={top}
        >
            <div>Do you want to <b>{titleType}</b> BFLA warnings?</div>
            {loading && <Loader />}
        </Modal>
    );
};

export default BflaModal;
