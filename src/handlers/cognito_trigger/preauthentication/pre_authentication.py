# -*- coding: utf-8 -*-
import os
import json
import logging
from lambda_base import LambdaBase
from jsonschema import ValidationError
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from not_authorized_error import NotAuthorizedError


class PreAuthentication(LambdaBase):
    def get_schema(self):
        pass

    def validate_params(self):
        pass

    def exec_main_proc(self):
        params = self.event
        external_provider_users_table = self.dynamodb.Table(os.environ['EXTERNAL_PROVIDER_USERS_TABLE_NAME'])
        external_provider_user = external_provider_users_table.get_item(Key={
            'external_provider_user_id': params['userName']
        }).get('Item')
        if external_provider_user is None:
            try:
                external_provider_users = external_provider_users_table.query(
                    IndexName="user_id-index",
                    KeyConditionExpression=Key('user_id').eq(params['userName'])
                )
                if external_provider_users.get('Count') == 1:
                    external_provider_user = external_provider_users.get('Items')[0]
            except ClientError as e:
                logging.fatal(e)
                return {
                    'statusCode': 500,
                    'body': json.dumps({'message': 'Internal server error'})
                }

        # ExternalProviderLoginのケース
        if self.__is_external_provider_login_validation_data(params):
            return self.event
        # 通常SignInのケース
        elif (external_provider_user is None) and (params['request']['validationData'] == {}):
            return self.event
        # ValidationDataが存在しない場合のadmin_initiate_authコマンドでのSignInのケース
        elif (external_provider_user is None) and (params['request'].get('validationData') is None):
            raise NotAuthorizedError('Forbidden')
        else:
            raise ValidationError('Please login with registered external provider')

    @staticmethod
    def __is_external_provider_login_validation_data(params):
        if (('EXTERNAL_PROVIDER_LOGIN_MARK' in params['request']['validationData']) and
           (os.environ['EXTERNAL_PROVIDER_LOGIN_MARK'] == params['request']['validationData']['EXTERNAL_PROVIDER_LOGIN_MARK'])):
            return True
        return False
