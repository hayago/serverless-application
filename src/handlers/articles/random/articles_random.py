# -*- coding: utf-8 -*-
import os
import json
import settings
from lambda_base import LambdaBase
from decimal_encoder import DecimalEncoder


class ArticlesRandom(LambdaBase):
    def get_schema(self):
        return {
            'type': 'object',
            'properties': {
                'article_id': settings.parameters['article_id']
            },
            'required': []
        }

    def validate_params(self):
        None

    def exec_main_proc(self):
        article_id = ArticlesRandom.__get_random_article()

        article_info_table = self.dynamodb.Table(os.environ['ARTICLE_INFO_TABLE_NAME'])
        article_content_table = self.dynamodb.Table(os.environ['ARTICLE_CONTENT_TABLE_NAME'])

        article_info = article_info_table.get_item(Key={'article_id': article_id}).get('Item')
        article_content = article_content_table.get_item(Key={'article_id': article_id}).get('Item')

        if article_info is None or article_content is None:
            return {
                'statusCode': 404,
                'body': json.dumps({'message': 'Record Not Found'})
            }

        article_content.pop('paid_body', None)
        article_info.update(article_content)

        return {
            'statusCode': 200,
            'body': json.dumps(article_info, cls=DecimalEncoder)
        }

    @staticmethod
    def __get_random_article():
        # TODO:
        return '8pzb0D0LV52E'
