def calculate_risk(df):
    df['risk_score'] = 0

    df.loc[df['failed_attempts'] > 5, 'risk_score'] += 8
    df.loc[df['login_hour'] < 4, 'risk_score'] += 5
    df.loc[df['anomaly'] == -1, 'risk_score'] += 10

    return df