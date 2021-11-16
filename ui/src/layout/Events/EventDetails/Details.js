import React from 'react';
import { useHistory } from 'react-router-dom';
import TitleValueDisplay, { TitleValueDisplayRow } from 'components/TitleValueDisplay';
import { utils } from 'components/Table';
import StatusIndicator from 'components/StatusIndicator';
import BflaStatusIcon, {BFLA_STATUS_TYPES_MAP} from 'components/BflaStatusIcon';
import Tag from 'components/Tag';
import Button from 'components/Button';

const Details = ({data}) => {
    const {id, method, statusCode, path, query, sourceIP, destinationIP, destinationPort, hostSpecName, apiInfoId, apiType,
        sourceK8sObject, destinationK8sObject, bflaStatus} = data;

    const history = useHistory();

    return (
        <div>
            <TitleValueDisplayRow>
                <TitleValueDisplay title="Method"><Tag>{method}</Tag></TitleValueDisplay>
                <TitleValueDisplay title="Status code"><StatusIndicator title={statusCode} isError={statusCode >= 400} /></TitleValueDisplay>
                <TitleValueDisplay title="Path" className="path-display">{path}</TitleValueDisplay>
                <TitleValueDisplay title="Query" className="query-display">{query}</TitleValueDisplay>
            </TitleValueDisplayRow>
            <TitleValueDisplayRow>
                <TitleValueDisplay title="Source">{sourceIP}</TitleValueDisplay>
                <TitleValueDisplay title="Destination">{destinationIP}</TitleValueDisplay>
                <TitleValueDisplay title="Destination port">{destinationPort}</TitleValueDisplay>
            </TitleValueDisplayRow>
            <TitleValueDisplayRow>
                <TitleValueDisplay title="Source Name">{sourceK8sObject.name}</TitleValueDisplay>
                <TitleValueDisplay title="Destination Name">{destinationK8sObject.name}</TitleValueDisplay>
                <TitleValueDisplay className="bfla-status" title={ <div className="bfla-status-title"><span>BFLA</span>{bflaStatus && <BflaStatusIcon id={id} bflaStatusType={bflaStatus} /> }</div> }>{bflaStatus ? <BflaStatus id={id} bflaStatus={bflaStatus} sourceName={sourceK8sObject.name}/> : <utils.EmptyValue />}</TitleValueDisplay>
            </TitleValueDisplayRow>
            <TitleValueDisplayRow>
                <TitleValueDisplay title="Source Kind">{sourceK8sObject.kind}</TitleValueDisplay>
                <TitleValueDisplay title="Destination Kind">{destinationK8sObject.kind}</TitleValueDisplay>
            </TitleValueDisplayRow>
            <TitleValueDisplayRow>
                <TitleValueDisplay title="spec" className="spec-display">
                    {!!apiInfoId ? <Button secondary onClick={() => history.push(`/inventory/${apiType}/${apiInfoId}`)}>{hostSpecName}</Button> : hostSpecName}
                </TitleValueDisplay>
            </TitleValueDisplayRow>
        </div>
    )
}

const BflaStatus = ({id, bflaStatus, sourceName}) => {
    const {SUSPICIOUS_SRC_DENIED, SUSPICIOUS_SRC_ALLOWED} = BFLA_STATUS_TYPES_MAP;
    const {value} = BFLA_STATUS_TYPES_MAP[bflaStatus] || {};

    let statusText;
    if (value === SUSPICIOUS_SRC_DENIED.value) {
        statusText = <div>
                         <p>The pod <b><em>{sourceName}</em></b> made this call to the API.</p>
                         This looks suspicious, as it would represent a violation of the current authorization model.  The API server correctly rejected the call
                     </div>;
    }

    if (value === SUSPICIOUS_SRC_ALLOWED.value) {
        statusText = <div>
                         <p>The pod <b><em>{sourceName}</em></b> made this call to the API.</p>
                         <p>This looks suspicious, as it represents a violation of the current authorization model.
                             Moreover, the API server accepted the call, which implies a possible Broken Function Level Authorisation.
                         </p>
                         <p>Please verify authorisation implementation in the API server.</p>
                     </div>;
    }

    return (
        <span>
            {statusText}
        </span>
    );
};

export default Details;
