import React, { useState, useEffect, useRef } from 'react';
import { useFetch } from 'hooks';
import TitleValueDisplay, { TitleValueDisplayRow } from 'components/TitleValueDisplay';
import Loader from 'components/Loader';

import './authorized.scss';

const Authorized = ({namespace, method, path, inventoryName}) => {
    const [{loading, data}] = useFetch(`authorizationModel/${namespace}`);
    const [audience, setAudience] = useState([]);

    useEffect(() => {
        if (!loading && data) {
            const { services } = data || {};
            const { operations } = services ? (services[inventoryName] || []) : [];
            const a = operations.filter((item) => {
                return item.method === method && item.path === path;
            });
            setAudience(a);
        }
    }, [data, loading, setAudience, inventoryName, method, path]);

    return (
        <div className="authorized-wrapper">
            <div className="authorized-title">Authorized</div>
            <div className="authorized-content">
                {loading ? <Loader /> :
                 <div>{
                        audience.map((a) => {
                            return a.audience.map((item, idx) => (
                                <TitleValueDisplayRow key={idx}>
                                    <TitleValueDisplay>{item.name}</TitleValueDisplay>
                                </TitleValueDisplayRow>
                            ));
                        })
                      }
                 </div>
                }
            </div>
        </div>
    );
}

export default Authorized;
