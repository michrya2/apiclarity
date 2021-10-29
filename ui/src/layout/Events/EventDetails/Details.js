import React from 'react';
import { useHistory } from 'react-router-dom';
import TitleValueDisplay, { TitleValueDisplayRow } from 'components/TitleValueDisplay';
import StatusIndicator from 'components/StatusIndicator';
import Tag from 'components/Tag';
import Button from 'components/Button';

const Details = ({data}) => {
    const {method, statusCode, path, query, sourceIP, destinationIP, destinationPort, hostSpecName, apiInfoId, apiType,
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
                <TitleValueDisplay title="BFLA">{bflaStatus}</TitleValueDisplay>
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

export default Details;